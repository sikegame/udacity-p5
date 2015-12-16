-- Catalog Database Configuration
-- Author: Shinsuke JJ Ikegame
-- Date: December 16, 2015

-- Create a user for Catalog App
CREATE USER catalog WITH PASSWORD 'udacity';

-- Create a database
CREATE DATABASE catalog;

-- Grant privileges needed to access the database
GRANT ALL PRIVILEGES ON DATABASE catalog TO catalog;