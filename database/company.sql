PRAGMA foreign_keys = ON;

-- ##### ROLES - INIT ##### --
DROP TABLE IF EXISTS roles;

CREATE TABLE roles(
    role_pk         TEXT,
    role_name       TEXT,
    PRIMARY KEY(role_pk)
);

-- ##### ROLES - SEED  ##### --
INSERT INTO roles VALUES('0', 'customer');
INSERT INTO roles VALUES('1', 'partner');
INSERT INTO roles VALUES('2', 'admin');

SELECT * FROM roles;


-- ##### USERS - INIT ##### --
DROP TABLE IF EXISTS users;

CREATE TABLE users(
    user_pk             TEXT,
    user_role_fk        TEXT,
    user_username       TEXT,
    user_name           TEXT,
    user_last_name      TEXT,
    user_email          TEXT UNIQUE,
    user_password       TEXT,
    user_is_blocked     TEXT DEFAULT 0,
    user_is_verified    TEXT DEFAULT 0,
    user_created_at     TEXT DEFAULT CURRENT_TIMESTAMP,
    user_updated_at     TEXT DEFAULT CURRENT_TIMESTAMP,
    user_deleted_at     TEXT DEFAULT 0,
    FOREIGN KEY(user_role_fk) REFERENCES roles(role_pk) ON DELETE CASCADE
    PRIMARY KEY(user_pk)
) WITHOUT ROWID; -- Without ROWID is only if we want to decide PK ourselves

-- ##### USERS - SEED ##### --
INSERT INTO users(user_pk, user_role_fk, user_username, user_name, user_last_name, user_email, user_password) VALUES ('1', '1', 'dirty_ranch', 'ole', 'olesen', 'ole@partner.dk', '1234578');
INSERT INTO users(user_pk, user_role_fk, user_username, user_name, user_last_name, user_email, user_password) VALUES ('2', '0', 'cowboy', 'anders', 'andersen', 'anders@customer.dk', '1234578');

SELECT * FROM users;

-- ##### PROPERTIES - INIT ##### --
DROP TABLE IF EXISTS properties;

CREATE TABLE properties(
    property_pk                 TEXT UNIQUE,
    property_user_fk            TEXT,
    property_booking_fk         TEXT,
    property_description        TEXT,
    property_price_pr_night     REAL,
    property_images             TEXT,
    property_rating             REAL,
    property_lat                TEXT,
    property_lon                TEXT,
    property_is_blocked         TEXT,
    property_created_at         INTEGER DEFAULT CURRENT_TIMESTAMP,
    property_updated_at         TEXT DEFAULT CURRENT_TIMESTAMP,
    property_deleted_at         TEXT DEFAULT 0,
    FOREIGN KEY(property_user_fk) REFERENCES users(user_pk) ON DELETE CASCADE,
    PRIMARY KEY(property_pk)
) WITHOUT ROWID;

-- ##### PROPERTIES - SEED ##### --
-- INSERT INTO properties VALUES ('0', '0', '0', 'one is a house', 1337, 'one.jpg', 4.5, 55.2001, 47.1240, '0', '', '', '');
INSERT INTO properties(
    property_pk, property_user_fk, property_booking_fk, 
    property_description, property_price_pr_night, property_images, property_rating, 
    property_lat, property_lon, property_is_blocked)
    VALUES('1', '1', '0', 'one is a house', 1337, 'one.jpg', 4.5, 55.2001, 47.1240, '0');


SELECT * FROM properties;

-- ##### BOOKING - INIT ##### --
DROP TABLE IF EXISTS bookings;

CREATE TABLE bookings(
    booking_pk              TEXT UNIQUE,
    booking_user_fk         TEXT,
    booking_property_fk     TEXT,
    FOREIGN KEY(booking_user_fk) REFERENCES users(user_pk) ON DELETE CASCADE,
    FOREIGN KEY(booking_property_fk) REFERENCES properties(property_pk) ON DELETE CASCADE,
    PRIMARY KEY(booking_pk)
) WITHOUT ROWID;

-- ##### BOOKINGS - TRIGGER ##### --
CREATE TRIGGER update_property_booking_fk
AFTER INSERT ON bookings
FOR EACH ROW
BEGIN
    UPDATE properties
    SET property_booking_fk = NEW.booking_pk
    WHERE property_pk = NEW.booking_property_fk;
END;

-- ##### BOOKINGS - SEED ##### --
INSERT INTO bookings VALUES('1', '2', '1');

SELECT * from bookings;
-- ##### BOOKINGS - TRIGGER DEMO ##### --
SELECT * from properties;