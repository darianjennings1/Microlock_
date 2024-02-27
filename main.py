from flask import Flask, request, url_for, render_template, redirect, send_file
from flask_fontawesome import FontAwesome
from crypto import generate_key_pair, load_key, get_plaintext_pub_key, load_pub_key_from_plaintext, lock_message, parse_full_secret_message ,encode_payload, unlock_message
from handle_secure_contact import create_secure_contact, get_secure_contact
from datetime import timedelta

# instance of Flask web app --- test
app = Flask(__name__, template_folder='templates', static_folder='statics')
app.permanent_session_lifetime = timedelta(seconds=10)
fa = FontAwesome(app)

session_user = ""
session_pub_key = ""
session_priv_key = ""

# default page is login
@app.route("/", methods = ['POST', 'GET'])
def login():
    global session_user
    global session_pub_key
    global session_priv_key
    global session_sc
    if request.method  == 'POST':
        form_data = request.form
        user = form_data['user']
        passw = form_data['pass']
        #print(user + " " + passw)
        pub_key = load_key(user,'pub')
        priv_key = load_key(user,'priv',passw)
        sc,_,_ = get_secure_contact(user)
        if pub_key == -1 or priv_key == -1 or sc == -1:
            return redirect(url_for("error"))
        else:
            session_user = user
            session_pub_key = pub_key
            session_priv_key = priv_key
            return redirect(url_for("home"))
    else:
        return render_template("login.html")

# error page
@app.route("/error")
def error():
    return render_template("error.html")

# accessed from login page button
@app.route("/createAccount", methods = ['POST', 'GET'])
def createAccount():
    if request.method  == 'POST':
        form_data = request.form
        fName = form_data['fName']
        lName = form_data['lName']
        email = form_data['email']
        passw = form_data['pass']
        
        user_name = f"{fName.lower().rstrip()}_{lName.lower().rstrip()}"
        generate_key_pair(user_name,passw)
        pub_key = get_plaintext_pub_key(user_name)
        create_secure_contact(user_name, fName, lName, email, pub_key)

        return redirect(url_for("new_account",username=user_name))
    else:
        return render_template("createAccount.html")

@app.route('/new_account')
@app.route('/new_account/<username>')
def new_account(username):
    return render_template('new_account.html', username=username)

# home serves as about page
@app.route("/home")
def home():
    return render_template("home.html")

# lock a message
@app.route("/lock", methods = ['POST', 'GET'])
def lock():
    if request.method == 'POST': 
        form_data = request.form
        tuser = form_data['ruser']
        ptext = form_data['ptext_mess']
        name, email, ptxt_pub_key = get_secure_contact(tuser)
        if name == -1:
            return redirect(url_for("error_2", username=tuser))
        else:
            pub_key = load_pub_key_from_plaintext(ptxt_pub_key)
            my_name,my_email,my_public_key = get_secure_contact(session_user)
            locked_message = encode_payload(lock_message(session_priv_key, pub_key, ptext))
            return render_template('locked_message.html',name=name,email=email,my_name=my_name, my_email=my_email, my_public_key=my_public_key,locked_message=locked_message)
    else:
        return render_template("lock.html")

@app.route('/error_2')
@app.route('/error_2/<username>')
def error_2(username):
    return render_template('error_2.html', username=username)

# unlock a message
@app.route("/unlock", methods = ['POST', 'GET'])
def unlock():
    if request.method == 'POST':
        form_data = request.form
        ctext = form_data['sMess']
        sender_un, sender_em, ptxt_sender_key, fsp = parse_full_secret_message(ctext)
        sender_key = load_pub_key_from_plaintext(ptxt_sender_key)
        unlocked_message,v = unlock_message(sender_key,session_priv_key,fsp)
        verified = ""
        if v:
            verified = "Message is verified to be from sender."
        else:
            verified = "WARNING: Message is not verified to be from sender!"
        return render_template('unlocked_message.html',name = sender_un, email = sender_em, umess=unlocked_message,verified=verified)
    else:
        return render_template("unlock.html")

# create and import/export contacts
@app.route("/contacts", methods = ['POST', 'GET'])
def contacts():
    if request.method == 'POST':
        f = request.files['file']
        f.save(f"./contacts/{f.filename}")  
        username = f.filename.split(".")[0]
        return redirect(url_for("contact_imported", username=username))  
    else:
        return render_template("contacts.html")

@app.route("/import_manual_contact", methods = ['POST', 'GET'])
def import_manual_contact():
    if request.method == 'POST':
        form_data = request.form
        fName = form_data['fName']
        lName = form_data['lName']
        email = form_data['email']
        pkey = form_data['pkey']
        username = f"{fName.lower().rstrip()}_{lName.lower().rstrip()}"
        create_secure_contact(username,fName,lName,email,pkey)
        return redirect(url_for("contact_imported", username=username))  
    else:
        return render_template("import_manual_contact.html") 

@app.route("/export_contact")
def export_contact():
    path=f"./contacts/{session_user}.txt"
    return send_file(path,as_attachment=True)

@app.route('/contact_imported')
@app.route('/contact_imported/<username>')
def contact_imported(username):
    return render_template('contact_imported.html', username=username)


if __name__ == "__main__":
    app.run(debug=True)