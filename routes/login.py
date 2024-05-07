from bottle import post, response, request
from icecream import ic
import x
import bcrypt

##############################
@post("/login")
def _():
  try:
    user_email = x.validate_user_email()
    user_password = x.validate_user_password()
    
    db = x.db()
    q = db.execute('SELECT * FROM users WHERE user_email = ? LIMIT 1', (user_email,))
    user = q.fetchone()
    ic(user['user_is_verified'])
    if user:
        if not bcrypt.checkpw(user_password.encode(), user["user_password"]): raise Exception("Invalid credentials", 400)
        if '1' in user['user_is_verified']:
            response.set_cookie("user", user, secret=x.COOKIE_SECRET, httponly=True, secure=x.is_cookie_https())
            return """
                <template mix-redirect="/" is_logged=True>
                </template>
            """
        else:
            return """
                <template mix-redirect="/not_verified" is_logged=False>
                </template>
            """
    else:
        return """
            <template mix-target="#error" mix-replace>
                <div id="error">User doesn't exist</div>
            </template>
        """
  except Exception as ex:
    print(f"------------------------------------{ex}------------------------------------")
    if "user_password" in ex.args[1]:
        return """
            <template mix-target="#error" mix-replace>
                <div id="error">User password invalid</div>
            </template>
        """
    if "user_email" in ex.args[1]:
        return """
            <template mix-target="#error" mix-replace>
                <div id="error">User email invalid</div>
            </template>
        """

    return """
        <template mix-target="#error" mix-replace>
            <div  mix-ttl="2000">System under maintainence</div>
        </template>
    """
  finally:
    if "db" in locals():
        db.close()