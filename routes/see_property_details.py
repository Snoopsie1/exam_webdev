from bottle import get, template
from icecream import ic
import x

@get('/property/<property_pk>')
def _(property_pk):
    try:
        db = x.db()
        q = db.execute("SELECT * from properties WHERE property_pk = ?", (property_pk,))
        fetched_property = q.fetchone()
        property_images = fetched_property['property_images'].split(',')
        try:
            is_logged = False
            if(x.validate_user_logged() != None): is_logged = True;
        finally:
            ic(is_logged)
            return template("property_details", property_images=property_images, property=fetched_property, is_logged=is_logged)
    except Exception as ex:
        ic(ex)
    finally:
        if "db" in locals():
            db.close()

