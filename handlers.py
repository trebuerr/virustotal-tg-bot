import io
import requests
import asyncio

from aiogram import Router, types, F
from aiogram.types import Message
from aiogram.filters import CommandStart


url_scan = "https://www.virustotal.com/vtapi/v2/file/scan"
url_report = "https://www.virustotal.com/vtapi/v2/file/report"
api_key = "1b2d7f20238acdd42938d72d3d7373c37d1d3930fa1d61ead7b7e1cc94414648" 

router = Router()

async def check_result(scan_id: str | int):
    report_params = {'apikey': f'{api_key}', 'resource': f'{scan_id}'}
    report_response = requests.Response()
    response_code = 0
    status_code = 0
    count = 0
    while count < 10:
        await asyncio.sleep(30)
        try:
            report_response = requests.get(url_report, params=report_params)
            status_code = report_response.status_code
            if status_code == 200:
                response_code = report_response.json().get('response_code', 0)
                report_data = report_response.json()
                if response_code == 1:
                    break
            else:
                print(f"ст код {status_code}")
        except:
            print("ошибка при выполнении запроса")
        count += 1

    if report_data.get('response_code') == 1:
        virus = report_data.get('positives', 0) 
        total = report_data.get('total', 0)
        result_text = (
            f"Результат проверки:\n"
            f"Найдено угроз: {virus} из {total}\n"
        )
    else:
        result_text = (
            f"Результат проверки:\n"
            f"Проверка завершена с ошибкой! Попробуйте еще раз! {report_data} {response_code} {scan_id} {status_code}"
        )
    return result_text

@router.message(CommandStart())
async def cmd_start(message: Message):
    await message.answer('Отправьте файл для проверки')
    await message.answer('Файл должен быть менее 32mb')

@router.message(F.document)
async def handle_doc(message: types.Message):
    file_info = await message.bot.get_file(message.document.file_id)
    file_path = file_info.file_path
    destination = io.BytesIO()
    await message.bot.download_file(file_path, destination)
    destination.seek(0)
    
    files = {'file': (message.document.file_name, destination)}
    params = {'apikey': api_key}
    
    
    response = requests.post(url_scan, files=files, params=params)
    await message.answer("Пожалуйста, подождите")
    
    data = response.json()
    scan_id = data.get('scan_id')
    
    if response.status_code == 200:
        await message.answer("Файл отправлен на проверку, ожидайте")
        res = await check_result(scan_id)
        await message.answer(res)
    else:
        await message.answer(f"Ошибка загрузки! Код ответа: {response.status_code}. Текст: {response.text}")