# Shopping Cart Service - Web Programming Midterm Project

## Overview
This project is a midterm submission for the Web Programming course, demonstrating a basic implementation of a Shopping Cart Service. The application is a RESTful API built using Go (Golang), enabling users to manage shopping baskets with create, read, update, and delete (CRUD) operations. It incorporates JWT (JSON Web Tokens) for user authentication, ensuring secure access and manipulation of data.

## Setup and Installation

1. install Go.

    Ensure Go is installed on your system. Download it from the official Go website if needed.

2. Clone the Repository

    Clone this repository to your local machine using:
    - git clone https://github.com/IAmirKhani/web-programming-course.git

3. Install Dependencies:
    > cd midterm

    > cd shopping-cart

    > go mod tidy
    
4. Run the Application:
    > go run main.go models.go


## API Endpoints

- 'POST /signup': Register a new user.
- 'POST /login': Authenticate a user and return a JWT.
- 'GET /basket/': Retrieve all baskets for the authenticated user.
- 'POST /basket/': Create a new basket.
- 'GET /basket/{id}': Retrieve a specific basket.
- 'PATCH /basket/{id}': Update a specific basket.
- 'DELETE /basket/{id}': Delete a specific basket.

