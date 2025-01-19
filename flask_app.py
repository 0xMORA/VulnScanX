from flask import Flask,render_template,redirect,url_for,request,session,flash
flask_app=Flask(__name__)

flask_app.secret_key="hello"


#homepage
@flask_app.route("/",methods=["GET","POST"])
def home():
        return render_template("index.html",
                            title="/",
                            custom_css="home",
                            custom_script="home",)

        



if __name__=="__main__":
    flask_app.run(host='127.0.0.1',port=80,debug=True)
