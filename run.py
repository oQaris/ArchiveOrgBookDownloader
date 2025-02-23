import os
import re
from io import BytesIO
from typing import Iterable, Callable, Iterator

import requests
from PIL import Image
from PIL.ImageFile import ImageFile
from requests import HTTPError
from tqdm import tqdm

loan_service = "https://archive.org/services/loans/loan"

# Общие заголовки для запросов
headers = lambda book_id: {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6",
    "Referer": f"https://archive.org/details/{book_id}/page/1/mode/1up",
    "Origin": "https://archive.org"
}


def borrow_book(cookies: dict[str, str], book_id: str):
    # Используем формат multipart/form-data через параметр files
    files = {
        "action": (None, "browse_book"),
        "identifier": (None, book_id)
    }
    response = requests.post(loan_service, files=files, headers=headers(book_id), cookies=cookies)
    if response.ok:
        try:
            json_resp = response.json()
            if not json_resp.get("success"):
                raise RuntimeError(f"Не удалось забронировать книгу, неверный ответ сервера: {response.content}")
        except Exception as e:
            raise RuntimeError(f"Ошибка при обработке ответа бронирования книги: {e}")
    else:
        raise RuntimeError(f"Ошибка при бронировании книги: {response.content}")


def update_token(cookies: dict[str, str], book_id: str) -> dict[str, str]:
    files = {
        "action": (None, "create_token"),
        "identifier": (None, book_id)
    }
    response = requests.post(loan_service, files=files, headers=headers(book_id), cookies=cookies)
    response.raise_for_status()

    json_resp = response.json()
    if json_resp.get("success") and "token" in json_resp:
        new_token = json_resp["token"]
        cookies[f"loan-{book_id}"] = new_token
        return cookies
    else:
        raise RuntimeError(f"Не удалось обновить токен, неверный ответ сервера: {response.content}")


def login(username: str, password: str) -> dict[str, str]:
    files = {
        "username": (None, username),
        "password": (None, password),
        "remember": (None, "true"),
        "login": (None, "true"),
        "submit_by_js": (None, "true"),
    }
    cookies = {
        "test-cookie": "1",
        "view-search": "tiles",
        "showdetails-search": "",
        "br-loan-": "1",
    }

    url = f"https://archive.org/account/login"
    response = requests.post(url, files=files, headers=headers("book_id"), cookies=cookies) # book_id - заглушка

    # Получаем и устанавливаем из заголовка ответа set-cookie: logged-in-sig, logged-in-user
    cookies.update(response.cookies.get_dict())
    return cookies


def get_book_metadata(book_id: str, cookies: dict[str, str]) -> dict:
    details_url = f"https://archive.org/details/{book_id}"
    details_response = requests.get(details_url, headers=headers(book_id), cookies=cookies)
    cookies.update(details_response.cookies.get_dict())

    pattern = r'(?:itemPath=([^\\&]+)|server=([^\\&]+))'
    matches = re.findall(pattern, details_response.text)

    item_path = None
    server = None
    for match in matches:
        if match[0]:
            item_path = match[0]
        if match[1]:
            server = match[1]

    params = {
        "id": book_id,
        "itemPath": item_path,
        "server": server,
        "format": "jsonp",
        "subPrefix": book_id,
        "requestUri": f"/details/{book_id}"
    }
    response = requests.get(
        f"https://{server}/BookReader/BookReaderJSIA.php",
        params=params,
        headers=headers(book_id),
        cookies=cookies
    )
    if not response.ok:
        raise RuntimeError(f"Ошибка получения метаданных: {response.status_code} - {response.text}")
    return response.json()


def parse_image_urls(metadata: dict) -> list[str]:
    image_urls = []
    for page_group in metadata['data']['brOptions']['data']:
        for page in page_group:
            image_urls.append(page['uri'] + '&scale=2&rotate=0')
    return image_urls


def download_images(book_id: str, cookies: dict[str, str]) -> Iterator[ImageFile]:
    print("Получаем метаданные книги...")
    metadata = get_book_metadata(book_id, cookies)

    image_urls = parse_image_urls(metadata)
    total_pages = len(image_urls)
    print(f"Найдено страниц: {total_pages}")

    download_urls = metadata['data']['data']['downloadUrls']
    if download_urls:
        print("Эту книгу можно скачать бесплатно по ссылкам:")
        for url in download_urls:
            print(url[0] + ": https:" + url[1])
        return

    print("Бронируем книгу...")
    borrow_book(cookies, book_id)

    print("Обновляем токен...")
    cookies = update_token(cookies, book_id)

    progress_bar = tqdm(total=total_pages, desc="Скачивание книги", unit="page")
    for idx, image_url in enumerate(image_urls, 1):

        response = requests.get(image_url, headers=headers(book_id), cookies=cookies)
        if not response.ok:
            print(f"\nОшибка загрузки страницы {idx}, пытаемся обновить токен...")
            try:
                cookies = update_token(cookies, book_id)
            except HTTPError as e:
                if e.response.json()['error'] == 'You do not currently have this book borrowed.':
                    print(f"\nИстекло время бронирования книги, бронируем повторно...")
                    borrow_book(cookies, book_id)
                    cookies = update_token(cookies, book_id)
            response = requests.get(image_url, headers=headers(book_id), cookies=cookies)
            response.raise_for_status()

        img = Image.open(BytesIO(response.content))
        progress_bar.update(1)
        yield img

    progress_bar.close()
    print("Все страницы успешно загружены!")


def folder_image_supplier(folder_path: str, extensions=(".jpg", ".jpeg", ".png")) -> Iterator[ImageFile]:
    """
    Генератор, считывающий изображения из указанной папки.

    Аргументы:
        folder_path: путь к папке с изображениями.
        extensions: кортеж с допустимыми расширениями файлов.

    Возвращает:
        объекты PIL.Image, считанные с диска.
    """
    files = sorted(os.listdir(folder_path))
    filtered_files = [f for f in files if f.lower().endswith(extensions)]

    for idx, filename in enumerate(filtered_files, start=1):
        full_path = os.path.join(folder_path, filename)

        print(f"Считывание {idx}/{len(filtered_files)}: {full_path}")
        img = Image.open(full_path)
        yield img


def create_pdf_from_images(image_supplier: Callable[[], Iterable[ImageFile]], output_pdf):
    """
    Формирует и сохраняет PDF из изображений, полученных от поставщика.
    Если во время получения изображений произошла ошибка, итоговый файл будет иметь префикс 'partial_'.

    Аргументы:
        image_supplier: генератор или функция, возвращающая объекты PIL.Image.
        output_pdf: строка, имя итогового PDF-файла.
    """
    images = []
    error_occurred = False
    try:
        for img in image_supplier():
            if not isinstance(img, Image.Image):
                continue
            if img.mode != "RGB":
                img = img.convert("RGB")
            images.append(img)
    except BaseException as e:
        print(f"Ошибка при получении изображений: {e}")
        error_occurred = True

    if not images:
        print("Не найдено ни одного изображения для формирования PDF.")
        return

    # Если ошибка произошла во время получения изображений, добавляем префикс
    final_pdf = ("partial_" + output_pdf) if error_occurred else output_pdf

    images[0].save(
        final_pdf,
        "PDF",
        save_all=True,
        append_images=images[1:]
    )
    print(f"PDF успешно сохранён: {final_pdf}")


if __name__ == "__main__":
    user_ = input("Логин (почта): ")
    pass_ = input("Пароль: ")

    print("Подключение к archive.org...")
    cook_ = login(user_, pass_)

    # Примеры:
    # 1) pasta0000unse_m6m5 (бронь на час)
    # 2) eyebrow0000cosi (бронь на 14 дней)
    # 3) bwb_S0-ATJ-863 (бесплатная)
    # Ссылка вида - https://archive.org/details/eyebrow0000cosi
    id_ = "pasta0000unse_m6m5"

    create_pdf_from_images(lambda: download_images(id_, cook_), f"{id_}.pdf")
    # create_pdf_from_images(lambda: folder_image_supplier('pasta0000unse_m6m5'), "files_pasta.pdf")
