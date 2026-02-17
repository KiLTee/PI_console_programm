
"""!@file main.py
@brief Модуль запуска программы — анализатор информации об уязвимостях.
@author [Имя автора]
@date [Дата создания/обновления]
@details Программа реализует GUI-интерфейс для анализа данных об уязвимостях ПО,
включая парсинг Excel-файлов, формирование отчётов и расчёт CVSS.
"""


import tkinter as tk
from tkinter import messagebox, ttk, font, BOTH, Button, X
import multiprocessing as mp
import parse
import word


def change_dict(table_inf: any, bdu: any, key: any) -> None:
    """!@brief Заполняет словарь table_inf данными из структуры bdu по ключу key.
    @details Формирует структурированный словарь с метаданными об уязвимости,
    включая наименование, идентификатор, описание, класс, ПО, версию и другие атрибуты.
    @param table_inf Словарь (dict), который заполняется данными (выходной параметр).
    @param bdu Структура данных (dict/list) с исходной информацией об уязвимостях.
    @param key Ключ (str/int) для доступа к записи об уязвимости в структуре bdu.
    @return None (функция модифицирует table_inf «на месте»).
    @see Функция используется в handle_kla_vul() для формирования отчётов.
    """
    table_inf["Наименование уязвимости"] = bdu[key][1]
    table_inf["Идентификатор уязвимости"] = key
    table_inf["Идентификаторы других систем описаний уязвимостей"] = (
        bdu[key][18] if bdu[key][18] is not None else "-"
    )
    table_inf["Краткое описание уязвимости"] = (
        bdu[key][2] if bdu[key][2] is not None else "-"
    )
    table_inf["Класс уязвимости"] = bdu[key][8] if bdu[key][8] is not None else "-"
    table_inf["Наименование ПО"] = bdu[key][4] if bdu[key][4] is not None else "-"
    table_inf["Версия ПО"] = bdu[key][5] if bdu[key][4] is not None else "-"
    table_inf["Тип ПО"] = bdu[key][6] if bdu[key][4] is not None else "-"
    table_inf["Служба, которая используется для функционирования ПО"] = "-"
    table_inf["Язык программирования ПО"] = (
        bdu[key][19] if bdu[key][19] is not None else "-"
    )
    table_inf["Тип недостатка"] = "-"
    table_inf["Место возникновения уязвимости"] = (
        bdu[key][6] if bdu[key][6] is not None else "-"
    )
    table_inf["Идентификатор типа недостатка"] = (
        bdu[key][21] if bdu[key][21] is not None else "-"
    )
    table_inf["Наименование операционной системы и тип аппаратной платформы"] = (
        bdu[key][7] if bdu[key][7] is not None else "-"
    )
    table_inf["Дата выявления уязвимости"] = (
        bdu[key][9] if bdu[key][9] is not None else "-"
    )
    table_inf["Автор опубликовавший информацию о выявленной уязвимости"] = "-"
    table_inf["Способ (правило) обнаружения уязвимости"] = "-"
    table_inf["Критерии опасности уязвимости"] = (
        f"В соответствии с cvssv2 - {bdu[key][10]} \nВ соответствии с cvssv3 - {bdu[key][11]}"
    )
    table_inf["Степень опасности уязвимости"] = (
        bdu[key][12] if bdu[key][12] is not None else "-"
    )
    table_inf["Возможные меры по устранению уязвимости"] = (
        bdu[key][13] if bdu[key][13] is not None else "-"
    )
    table_inf["Ссылки на источники"] = (
        bdu[key][17] if bdu[key][17] is not None else "-"
    )
    table_inf["Прочая информация"] = bdu[key][3]


def main():
    """!@brief Основная функция программы — запуск GUI и обработка логики приложения.
    @details Инициализирует окно tkinter, создаёт закладки (notebook),
    размещает элементы управления (labels, entries, buttons) и связывает их с логикой.
    @return None
    """
    # --------------------------------Область с текстом содержания--------------------------------
    menu_text = [
        "Ниже, укажите ссылки на:",
        "Отчет об уязвимостях касперского:",
        "Список уязвимотсей Касперского (CVE_List):",
        "БДУ ФСТЭК:",
        "Перечень ПО:",
        "Директория хранения результата:",
        "Имя автора отчетов:",
    ]  # Текст Меню

    cvss_calc_text = ["В работе перенос на GUI"]  # Текст cvssv2 калькулятора

    pasrser_json_cve_text = ["В работе перенос на GUI"]  # Текст json парсера

    settings_text = ["Настройка ссылок:", ""]  # Текст Настроек

    info_text = [
        "Разработка ЦКИБ (г. Хабаровск)",
        "Версия 0.1",
    ]  # Текст из блока информации

    path_poumol = [
        "./Excel/Отчет об уязвимостях.xlsx",
        "./Excel/CveList_New.xlsx",
        "./Excel/vullist.xlsx",
        "./Excel/Перечень ПО.xlsx",
        "./Результаты",
    ]

    def make_markers():  
        """!@brief Создаёт структуру закладок (tabs) в GUI.
        @return Словарь с виджетами ttk.Frame для каждой закладки.
        @details Инициализирует ttk.Notebook и добавляет 5 закладок с уникальными метками.
        """
        result = {}
        tab = ttk.Notebook(root)
        main_marker = ttk.Frame(tab)
        result["Меню"] = main_marker
        cvss_calc_marker = ttk.Frame(tab)
        result["cvssv2 калькулятор"] = cvss_calc_marker
        settings_marker = ttk.Frame(tab)
        result["Настройки"] = settings_marker
        info_marker = ttk.Frame(tab)
        result["Информация"] = info_marker
        pasrser_json_cve_marker = ttk.Frame(tab)
        result["Парсинг json"] = pasrser_json_cve_marker
        tab.add(main_marker, text="Меню")
        tab.pack(expand=1, fill="both", side=tk.LEFT)
        tab.add(cvss_calc_marker, text="cvssv2 калькулятор")
        tab.pack(expand=1, fill="both", side=tk.LEFT)
        tab.add(pasrser_json_cve_marker, text="Парсинг json")
        tab.pack(expand=1, fill="both", side=tk.LEFT)
        tab.add(settings_marker, text="Настройки")
        tab.pack(expand=1, fill="both", side=tk.LEFT)
        tab.add(info_marker, text="Информация")
        tab.pack(expand=1, fill="both", side=tk.LEFT)
        return result

    def create_menu_marker(main_marker, menu_text):  # Закладка меню
        """!@brief Создаёт элементы закладки «Меню».
        @param main_marker Виджет ttk.Frame для размещения элементов.
        @param menu_text Список строк с подписями для labels.
        @details Размещает labels и entries для ввода путей к файлам и настроек.
        @return None
        """
        frame_lines = make_lines(len(menu_text), main_marker)
        make_lables(frame_lines, menu_text)
        entry_mass = make_entry(frame_lines)

        progressbar_ = make_progressbar(main_marker)

        start_button = Button(
            main_marker,
            text="Старт",
            width=20,
            height=2,
            command=lambda: start_program(progressbar_, entry_mass),
        )
        start_button.pack(anchor="nw", side=tk.LEFT)

    def create_cvss_calc_marker(
        cvss_calc_marker, cvss_calc_text
    ):  # Закладка cvssv2 калькулятора
        frame_lines = make_lines(len(cvss_calc_text), cvss_calc_marker)
        make_lables(frame_lines, cvss_calc_text)

    def create_cve_json_parser_marker(
        pasrser_json_cve_marker, pasrser_json_cve_text
    ):  # Закладка json парсера
        frame_lines = make_lines(len(cvss_calc_text), pasrser_json_cve_marker)
        make_lables(frame_lines, pasrser_json_cve_text)

    def create_settings_marker(settings_marker, settings_text):  # Закладка Настроек
        frame_lines = make_lines(len(settings_text), settings_marker)
        make_lables(frame_lines, settings_text)
        entry_mass = make_entry(frame_lines)

        start_button = Button(
            settings_marker, text="Сохранить", width=20, height=2, command=start_program
        )

        start_button.pack(anchor="nw", side=tk.LEFT)

    def create_info_marker(info_marker, info_text):  # Закладка с информацией
        frame_lines = make_lines(len(settings_text), info_marker)
        make_lables(frame_lines, info_text)

    # --------------------------------Область создания элементов--------------------------------
    def make_lines(max, place):
        mass = []
        for k in range(0, max):
            frame_top1 = ttk.Frame(place, borderwidth=1)
            frame_top1.pack(fill=BOTH)
            mass.append(frame_top1)
        return mass

    def make_lables(frame_lines, text_mass):
        for k, text in enumerate(text_mass):
            label1 = ttk.Label(
                frame_lines[k],
                relief="flat",
                font=font1,
                justify=tk.RIGHT,
                text=text,
            )
            label1.pack(anchor="nw")

    def make_entry(frame_lines):  # Функция для создания энтри каждому
        entry_mass = []
        for i in range(1, len(frame_lines)):
            entry = ttk.Entry(frame_lines[i], justify=tk.RIGHT, font=font1)
            entry.pack(anchor="nw", side=tk.LEFT, padx=0)
            entry_mass.append(entry)
        return entry_mass

    def make_progressbar(main_marker):
        frame_top1 = ttk.Frame(main_marker, borderwidth=1)
        frame_top1.pack(fill=BOTH)
        progressbar = ttk.Progressbar(
            frame_top1, orient="horizontal", mode="indeterminate"
        )
        progressbar.pack(fill=X, padx=10, pady=10)
        return progressbar

    # --------------------------------Область функций--------------------------------
    def take_values(entry_mass):
        """!@brief Извлекает значения из виджетов Entry.
        @param entry_mass Список виджетов ttk.Entry.
        @return Словарь {метка: значение} для всех полей ввода.
        @details Сопоставляет текст из entry с метками из menu_text.
        """
        result = {}
        for i in range(1, len(entry_mass) + 1):
            result[menu_text[i]] = entry_mass[i - 1].get()
        print(result)
        return result

    def handle_kla_vul(entry_dict):
        """!@brief Обрабатывает данные об уязвимостях и генерирует отчёты.
        @param entry_dict Словарь с путями к файлам и настройками из GUI.
        @details Парсит Excel-файлы, формирует таблицу уязвимостей и создаёт Word-документы.
        @see Использует функции parse.xlsx() и word.print_metodic().
        """
        table_inf = {}
        bdu = parse.xlsx(
            entry_dict["Отчет об уязвимостях касперского:"],
            entry_dict["Список уязвимотсей Касперского (CVE_List):"],
            entry_dict["БДУ ФСТЭК:"],
        )
        for key in bdu:
            change_dict(table_inf, bdu, key)
            word.print_metodic(
                table_inf,
                key,
                entry_dict["Имя автора отчетов:"],
                entry_dict["Директория хранения результата:"],
            )
        parse.make_base(bdu, entry_dict["Имя автора отчетов:"])

    def start_program(progressbar_, entry_mass):
        """!@brief Запускает основной процесс анализа при нажатии кнопки «Старт».
        @param progressbar_ Виджет ttk.Progressbar для индикации загрузки.
        @param entry_mass Список виджетов ttk.Entry с настройками.
        @details Валидирует входные данные, запускает парсинг в отдельном процессе.
        @return None
        """
        progressbar_.start()
        entry_dict = take_values(entry_mass)
        string_message = "Введите:"
        count_warning = 0
        answer = False
        for key in entry_dict:
            if entry_dict[key] == "":
                string_message += f"\n {key}"
                count_warning += 1
        if count_warning != 0:
            string_message += "\n\n Заполнить поля автоматическими значениями?"
            answer = messagebox.askyesno("Внимание!", string_message)
        if answer is True:
            for i in range(1, len(path_poumol) + 1):
                entry_dict[menu_text[i]] = path_poumol[i - 1]
            p = mp.Process(target=handle_kla_vul(entry_dict))
            p.start()
            progressbar_.stop()

        else:
            progressbar_.stop()
            return

    # --------------------------------Область GUI--------------------------------
    root = tk.Tk()
    root.title("Анализатор информации об уязвимостях")  # Заголовок окна
    root.geometry("+700+300")

    font1 = font.Font(
        family="Times New Roman",
        size=14,  # Настрйки текста:
        weight="normal",
        slant="roman",
    )
    # ---------------------------------------------------------------------------
    markers = make_markers()

    create_menu_marker(markers["Меню"], menu_text)
    create_cvss_calc_marker(markers["cvssv2 калькулятор"], cvss_calc_text)
    create_cve_json_parser_marker(markers["Парсинг json"], pasrser_json_cve_text)
    create_settings_marker(markers["Настройки"], settings_text)
    create_info_marker(markers["Информация"], info_text)
    # ---------------------------------------------------------------------------
    root.mainloop()


if __name__ == "__main__":
    main() # Запуск основной функции при исполнении скрипта

