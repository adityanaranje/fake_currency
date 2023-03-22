import streamlit as st
import hashlib
import sqlite3
import numpy as np
from keras.models import load_model
from PIL import Image
import cv2

st.sidebar.title("Fake Currency Detection")
st.sidebar.image("s1.jpg")

# Create a connection to the database
conn = sqlite3.connect('users.db')
c = conn.cursor()

# Create a table to store user information
c.execute('''CREATE TABLE IF NOT EXISTS users (username text, password text)''')



def fake_currency(imgg):
    IMAGE_SIZE = 64
    model = load_model('currency_model.h5')
    img = Image.open(imgg)

    img = img.resize((IMAGE_SIZE,IMAGE_SIZE))
    img = np.array(img)

    img = img.reshape(1,IMAGE_SIZE,IMAGE_SIZE,3)

    img = img.astype('float32')
    img = img / 255.0
    prediction = model.predict(img)
    Fake=np.argmax(prediction)

    if Fake == 0:
        cd="No Fake Currency detected"

    elif Fake == 1:
        cd="Fake Currency detected"
    return cd

def main():
    st.sidebar.title("Fake Currency Detection")
      
    #option = st.sidebar.selectbox("Options", ["Image","Video"])
    
    #if option == "Image":
    img = st.sidebar.file_uploader("Upload Image", type=["png","jpg","svg","jpeg"])
    
    if img:
        st.image(img, width=500)
        
        result = fake_currency(img)
        
        st.header(result)


    ## Video
    # if option=="Video":
    #     st.title("Onbuild")
        # st.title("Webcam Live Feed")
        # run = st.checkbox("Run")
        # FRAME_WINDOW = st.image([])
        # camera = cv2.VideoCapture(0)

        # while run:
        #     _, frame = camera.read()
        #     frame = cv2.resize(frame, (1000,700))
        #     frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        #     FRAME_WINDOW.image(frame)
        
        # camera.release()



def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def signup():
    st.write("Create a new account")
    username = st.text_input("Enter a username")
    password = st.text_input("Enter a password", type="password")
    confirm_password = st.text_input("Confirm your password", type="password")
    
    col1, col2 = st.columns(2)
    
    with col1:
        signup_button = st.button("SignUp")
    with col2:
        st.info("Login if already have account")
    
    if signup_button:
        if password != confirm_password:
            st.error("Passwords do not match")
            return
        hashed_password = hash_password(password)
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        st.success("You have successfully created an account. Go to login page")

def login():
    st.write("Login to your account")
    username = st.text_input("Enter your username")
    password = st.text_input("Enter your password", type="password")
    login_button = st.button("Login")
    
    if login_button:
        hashed_password = hash_password(password)
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
        user = c.fetchone()
        if user:
            st.success("You have successfully logged in")
            session_id = user[0] # Use the username as the session ID
            st.session_state['session_id'] = session_id
            
            st.info("Choose fake currency detection from options")
            
        else:
            st.error("Incorrect username or password")
   
            
def logout():
    st.session_state.pop('session_id', None)
    st.write("You have been logged out")    
    




menu = ["Signup","Login", "Logout","Detect With Image"]
if 'session_id' not in st.session_state:
    choice = st.sidebar.selectbox("Select an option", menu[:-2])
else:
    choice = st.sidebar.selectbox("Select an option", menu)

if choice == "Login":
    login()
elif choice == "Signup":
    signup()
elif choice == "Logout":
    logout()
elif choice == "Detect With Image":
    main()
else:
    st.write("Welcome back, " + st.session_state['session_id'])
