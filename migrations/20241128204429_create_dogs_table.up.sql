-- Add up migration script here

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS dogs (
    id UUID PRIMARY KEY NOT NULL DEFAULT (uuid_generate_v4()),
    name VARCHAR(255) NOT NULL,
    breed VARCHAR(255),
    color VARCHAR(255) NOT NULL,
    location VARCHAR(255),
    prooflevel INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create or replace the function to update the "updated_at" field
CREATE OR REPLACE FUNCTION update_updated_on_dogs()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create the trigger that will call the function before each update
CREATE TRIGGER update_dogs_updated_at
    BEFORE UPDATE
    ON dogs
    FOR EACH ROW
EXECUTE PROCEDURE update_updated_on_dogs();

CREATE TABLE IF NOT EXISTS zkptable (
    id UUID PRIMARY KEY NOT NULL DEFAULT (uuid_generate_v4()),
    dog_id UUID references dogs(id),
    public_input TEXT[]
);