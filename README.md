# Course Management API

This Flask-based API is a full-stack application designed for managing courses, users, and enrollments. The app is meant to be hosed on Google App Engine and integrates with Google Cloud Datastore for data storage, Google Cloud Storage for managing user avatars, and Auth0 for secure JWT-based authentication. Testing of the API was done using Postman for validating all endpoints.

## Features

- **User Authentication:**  
  Implements JWT verification and login using Auth0, ensuring secure access to API endpoints.

- **User Management:**  
  Supports retrieving user details and managing user avatars (upload, download, and deletion).

- **Course Management:**  
  Enables creation, retrieval, update, and deletion of courses. Courses are linked with instructor and student data.

- **Enrollment Management:**  
  Allows adding and removing students from courses while enforcing role-based access control.

## Prerequisites

- **Python 3.6+**
- **Flask**  
- **Google Cloud SDK**  
  Must have credentials set up for accessing Cloud Datastore and Cloud Storage.
- **Auth0 Account**  
  Potential users must be pre-configured with usernames and passwords


## API Endpoints
### Authentication
* **POST** `/users/login`

Generates a JWT for a registered user.

**Request Body:**
```
{
  "username": "user@example.com",
  "password": "yourpassword"
}
```
**Response:**
```
Status: 200
{
  "token": "JWT_TOKEN"
}

```

* **GET** `/decode`
Decodes the JWT from the Authorization header and returns the payload.

### User Management
* **GET** `/users`
Returns a list of all users (accessible by admin only).

**Request Body:**
```
None
```
**Response:**
```
Status: 200
[
{
"id": 5631671361601536,
"role": "student",
"sub": "auth0|664384d7829d72375c7a034d"
},
{
"id": 5632499082330112,
"role": "instructor",
"sub": "auth0|664383f2ad88a0630023ab9b"
}
]
```

* **GET** `/users/<user_id>`
Retrieves details of a specific user. Includes additional course info for instructors and students.
**Request Body:**
```
None
```
**Response:**
```
Status: 200
{
"avatar_url": "http://localhost:8080/users/5644004762845184/avatar",
"courses": [
"http://localhost:8080/courses/5744039651442688",
"http://localhost:8080/courses/5759318150348800"
],
"id": 5644004762845184,
"role": "instructor",
"sub": "auth0|6583ae12895d09a70ba1c7c5"
}
```

* **POST** `/users/<user_id>/avatar`
Upload the .png in the request as the avatar of the user’s avatar. If there is already an avatar for the user, it gets updated with the new file. Photos are stored in Google Cloud Storage. JWT is owned by user_id in the path parameter.

**Request Body:**
```
Form-data with one required key “file” with a .png extension
```
**Response:**
```
Status: 200
{
"avatar_url": "http://localhost:8080/users/5644004762845184/avatar"
}
```

* **GET** `/users/<user_id>/avatar`
Return the file stored in Google Cloud Storage as the user’s avatar.

**Request Body:**
```
None
```
**Response:**
```
Status: 200

```

* **DELETE** `/users/<user_id>/avatar`
Deletes the user's avatar.

**Request Body:**
```
None
```
**Response:**
```
Status: 204
```

### Course Management
* **POST** `/courses`
Creates a new course (admin only).

**Request Body:**
```
{
  "subject": "CS",
  "number": "101",
  "title": "Introduction to Computer Science",
  "term": "Fall 2025",
  "instructor_id": 12345
}
```

**Response:**
```
Status: 201 Created
{
"id": 5710353417633792,
"instructor_id": 5644004762845184,
"number": 493,
"self": "http://localhost:8080/courses/5710353417633792",
"subject": "CS",
"term": "fall-24",
"title": "Cloud Application Development"
}
```

* **GET** `/courses`
Retrieves a paginated list of courses. Supports query parameters:
  * page (default: 1)
  * limit (default: 3)
The property “next” is a URL with query parameters offset and limit set to correct values.
 
**Request Body:**
```
None
```
**Response:**
```
Status: 200 OK
{
"courses": [
{
"id": 5633378543992832,
"instructor_id": 5644004762845184,
"number": 493,
"self": "http://localhost:8080/courses/5633378543992832",
"subject": "CS",
"term": "fall-24",
"title": "Cloud Application Development"
},
{
"id": 5640825748848640,
"instructor_id": 5644004762845184,
"number": 492,
"self": "http://localhost:8080/courses/5640825748848640",
"subject": "CS",
"term": "fall-24",
"title": "Mobile App Development"
}
],
"next": "http://localhost:8080/courses?limit=3&offset=3"
}
```
    
* **GET** `/courses/<course_id>`
Retrieves details of a specific course without the list of students enrolled in the course.

**Request Body:**
```
None
```
**Response:**
```
Status: 200
{
"id": 5667525748588544,
"instructor_id": 5644004762845184,
"number": 493,
"self": "http://localhost:8080/courses/5667525748588544",
"subject": "CS",
"term": "fall-24",
"title": "Cloud Application Development"
}
```

* **PATCH** `/courses/<course_id>`
Updates course details (admin only). Must include the instructor_id field among others.

**Request Body:**
```
{
"instructor_id": 5644004762845184
}
```
**Response:**
```
Status: 200
{
"id": 5710353417633792,
"instructor_id": 5644004762845184,
"number": 493,
"self": "http://localhost:8080/courses/5710353417633792",
"subject": "CS",
"term": "fall-24",
"title": "Cloud Application Development"
}
```

* **DELETE** `/courses/<course_id>`
Deletes a course and its related enrollments (admin only).

**Request Body:**
```
None
```
**Response:**
```
Status: 204
```

### Enrollment Management
* **PATCH** `/courses/<course_id>/students`
Updates enrollments for a course by adding or removing student IDs.
**Request Body:**
```
{
"add": [
5642368648740864,
5714489739575296,
5636645067948032,
5646488461901824
],
"remove": [
]
}

```
**Response:**
```
Status: 200
```

* **GET** `/courses/<course_id>/students`
Retrieves a list of student IDs enrolled in the course.

**Request Body:**
```
None
```
**Response:**
```
Status: 200
[
5646488461901824,
5631671361601536,
5642368648740864
]
```

### Error Handling
The API returns JSON error responses with appropriate HTTP status codes:

* 400: Bad Request (invalid request body or missing fields)
* 401: Unauthorized (missing or invalid JWT) 
* 403: Forbidden (insufficient permissions)
* 404: Not Found (resource does not exist)
* 409: Conflict (invalid enrollment updates)
