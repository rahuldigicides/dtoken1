import json

# import requests
import os
import base64
import datetime
import random
import string
from pydantic import  BaseModel
from fastapi.middleware.cors import CORSMiddleware
import pymysql 

# ! MY simple TOken 
import jwt
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from datetime import datetime, timedelta
from fastapi import FastAPI,Depends,HTTPException,status, Security


class Userdata(BaseModel):
    userid: str
    password: str
    email: str
    role: str
    status: str
    company: str
    reporting: str
    blocked: int
    deleted: int
    name:str 
    phone:str

class Userlogin(BaseModel):
    username: str
    password: str

class Userup(BaseModel):
    userid: str
    newvalue: int

class Userextra(BaseModel):
    userid: str
    usercol: str
    colvalue: str

class Myuser(BaseModel):
    userid: str

class UserInDB(Userdata):
    password: str







# ! Database 
# db_name="digisides"
# db_user="root"
# db_password=""
# db_host="127.0.0.1"
# db_port="3306"
db_name="sql4500961"
db_user="sql4500961"
db_password="1GqlVcPjtS"
db_host="sql4.freemysqlhosting.net"
db_port="3306"


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get('/hello') 
def hello():
    return {"server":"uvicorn main:app --host 0.0.0.0 --port 8000"}

# ! Auth Handle File 
class AuthHandler():
    security = HTTPBearer()
    # pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    secret = 'SECRET'

    # def get_password_hash(self, password):
    #     return self.pwd_context.hash(password)

    # def verify_password(self, plain_password, hashed_password):
    #     return self.pwd_context.verify(plain_password, hashed_password)

    def encode_token(self, user_id):
        payload = {
            'exp': datetime.utcnow() + timedelta(days=0, minutes=60),
            'iat': datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            self.secret,
            algorithm='HS256'
        )

    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Signature has expired')
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail='Invalid token')

    def auth_wrapper(self, auth: HTTPAuthorizationCredentials = Security(security)):
        return self.decode_token(auth.credentials)

auth_handler = AuthHandler()



# ! Login 
@app.post("/userlogin")
async def user_login(udata:Userlogin):
    username = str(udata.username)
    password = str(udata.password)
    con = pymysql.connect(host=db_host, user=db_user, password=db_password, database=db_name, charset='utf8mb4',
                          cursorclass=pymysql.cursors.DictCursor)
    
    
    try:

        with con.cursor() as cur:

            cur.execute('select * from users where email=%s and password=%s and blocked=0',
                        (username, password))
            result =  cur.fetchall()
            
            con.commit()

            if len(result) > 0:
                token = auth_handler.encode_token(username)
                return {"token": token, "token_type": "bearer","status":status.HTTP_200_OK}
               
            else:
                raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
               

    finally:

        con.close()


@app.post("/register")
async def register_user(udata: Userdata):
    userid = udata.userid
    password = udata.password
    email = udata.email
    role = udata.role
    ustatus = udata.status
    company = udata.company
    reporting = udata.reporting
    blocked = udata.blocked
    deleted = udata.deleted 
    name=udata.name 
    phone=udata.phone

    con = pymysql.connect(host=db_host, user=db_user, password=db_password, database=db_name)


    try:

        with con.cursor() as cur:
            cur.execute('select * from users where email=%s',(email))
            data = cur.fetchall() 
            con.commit()
            if len(data) == 0:
                ############################create user ##############################
                cur.execute('INSERT INTO users VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s,%s ,%s)',
                            (userid, email, password, role, reporting, ustatus,company, blocked, deleted,name,phone))
                con.commit()

                # print('new user inserted')
                # "status":status.HTTP_200_OK
                return {"message":"User Created", "status":status.HTTP_201_CREATED}
                ##################################################################
            else:
                return {"message":"Dulicate user","status":409 }

    finally:

        con.close()

    return {"message": "user created!"}




@app.get("/userlist")
async def get_users(username=Depends(auth_handler.auth_wrapper)):

    con = pymysql.connect(host=db_host, user=db_user, password=db_password, database=db_name, charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)
    
    print("================= ",username)
    try:

        with con.cursor() as cur:

            cur.execute('select * from users'
                    )
            result = cur.fetchall()
            con.commit()

            print('new user inserted')

    finally:

        con.close()

    return {"data": result}




@app.put("/user")
async def update_user(udata: Userdata, username=Depends(auth_handler.auth_wrapper)):
    userid = udata.userid
    password = udata.password
    email = udata.email
    role = udata.role
    status = udata.status
    company = udata.company
    reporting = udata.reporting
    blocked = udata.blocked
    deleted = udata.deleted

    con = pymysql.connect(host=db_host, user=db_user, password=db_password, database=db_name)


    try:

        with con.cursor() as cur:

                ############################update user ##############################
                cur.execute('update users set email=%s, password=%s, role=%s, reporting=%s, status=%s, company=%s, blocked=%s, deleted=%s where userid=%s',
                            (email, password, role, reporting, status,company, blocked, deleted, userid))
                con.commit()
                ##################################################################


    finally:

        con.close()

    return {"message": "user updated!"}



@app.put("/user/delete")
async def delete_user(udata: Userup,  username=Depends(auth_handler.auth_wrapper)):
    userid = udata.userid
    newvalue = udata.newvalue


    con = pymysql.connect(host=db_host, user=db_user, password=db_password, database=db_name)


    try:

        with con.cursor() as cur:

                ############################update user ##############################
                cur.execute('update users set deleted=%s where userid=%s',
                            (newvalue, userid))
                con.commit()
                ##################################################################


    finally:

        con.close()

    return {"message": "user deleted!"}

@app.put("/user/block")
async def block_user(udata: Userup,  username=Depends(auth_handler.auth_wrapper)):
    userid = udata.userid
    newvalue = udata.newvalue


    con = pymysql.connect(host=db_host, user=db_user, password=db_password, database=db_name)


    try:

        with con.cursor() as cur:

                ############################update user ##############################
                cur.execute('update users set blocked=%s where userid=%s',
                            (newvalue, userid))
                con.commit()
                ##################################################################


    finally:

        con.close()

    return {"message": "user updated!"}

@app.post("/userdata", )
async def detail_user(udata: Userextra,  username=Depends(auth_handler.auth_wrapper)):
    userid = udata.userid
    usercol = udata.usercol
    colvalue = udata.colvalue


    con = pymysql.connect(host=db_host, user=db_user, password=db_password, database=db_name)


    try:

        with con.cursor() as cur:
            cur.execute('select * from userdata where usercol=%s and userid=%s',
                        (usercol, userid))
            data = cur.fetchall()
            con.commit()
            if len(data) == 0:
                ############################create user ##############################
                cur.execute('INSERT INTO userdata VALUES(%s, %s, %s)',
                            (userid, usercol, colvalue))
                con.commit()

                print('new user data inserted')
                ##################################################################
            else:
                return {"message":"Dulicate user data"}

    finally:

        con.close()

    return {"message": "user data created!"}


@app.get("/userdata/{userid}")
async def getdetail_user(userid,username=Depends(auth_handler.auth_wrapper)  ):
    userid = udata.userid

    con = pymysql.connect(host=db_host, user=db_user, password=db_password, database=db_name)

    try:

        with con.cursor() as cur:
            cur.execute('select * from userdata where userid=%s',
                        (userid))
            data = cur.fetchall()
            con.commit()


    finally:

        con.close()

    return {"message": "user extra data", "data": data}

# handler = Mangum(app)
# if __name__ == "__main__":
#     uvicorn.run(app, host="127.0.0.1",port=8000)