
from flask import Flask, request, jsonify, render_template, url_for, send_file
from google.cloud import datastore
from google.cloud.datastore.query import PropertyFilter
from google.cloud import storage

import requests
import json
import io
import uuid

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
client = datastore.Client()
storage_client = storage.Client()

PHOTO_BUCKET = 'cms_photos'

# ERROR MESSAGES
ERROR_400 = {"Error": "The request body is invalid"}
ERROR_401 = {"Error": "Unauthorized"}
ERROR_403 = {"Error": "You don't have permission on this resource"}
ERROR_404 = {"Error": "Not found"}
ERROR_409 = {"Error": "Enrollment data is invalid"}

# Update the values of the following 3 variables
CLIENT_ID = 'client-id'
CLIENT_SECRET = 'client-secret'
DOMAIN = 'dev-domain.us.auth0.com'
ALGORITHMS = ["RS256"]

oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_jwt(request):
    """Verify the JWT in the request's Authorization header"""
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                         "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())

    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)
        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                         "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


@app.route('/users/login', methods=['POST'])
def login_user():
    """Generate a JWT from the Auth0 domain and return it
    Request: JSON body with 2 properties with "username" and "password"
        of a user registered with this Auth0 domain
    Response: JSON with the JWT as the value of the property id_token"""
    content = request.get_json()
    if not content:
        return jsonify(ERROR_400), 400
    if "username" not in content:
        return jsonify(ERROR_400), 400
    if "password" not in content:
        return jsonify(ERROR_400), 400

    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password', 'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    if r.status_code == 401:
        return jsonify(ERROR_401), 401

    response_json = r.json()
    id_token = response_json.get("id_token")

    if not id_token:
        return jsonify(ERROR_401), 401
    response = jsonify({"token": id_token})
    response.headers.set('Content-Type', 'application/json')
    return response, 200


@app.route('/users', methods=['GET'])
def get_users():
    """return all users"""
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return jsonify(ERROR_401), 401

    if payload['nickname'] != 'admin1':
        return jsonify(ERROR_403), 403

    query = client.query(kind='users')
    users = list(query.fetch())

    response = []
    for user in users:
        user_data = {
            "id": user.id,
            "role": user.get("role", ""),
            "sub": user.get("sub", "")
        }
        response.append(user_data)

    return jsonify(response), 200


@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return jsonify(ERROR_401), 401

    user_key = client.key('users', user_id)
    user = client.get(user_key)

    if not user:
        return jsonify(ERROR_403), 403

    if user['role'] != 'admin':
        if payload['sub'] != user['sub']:
            return jsonify(ERROR_403), 403

    user_data = {
        "id": user.id,
        "role": user.get("role", ""),
        "sub": user.get("sub", "")
    }
    avatar_location = user.get("avatar_location")
    if avatar_location:
        user_data["avatar_url"] = f"{request.base_url}/avatar"

    # user is the course instructor
    if user['role'] == 'instructor':
        instruct_query = client.query(kind='courses')
        instruct_query.add_filter(
            filter=PropertyFilter('instructor_id', '=', user_id))
        courses = list(instruct_query.fetch())

        courses_list = []
        for course in courses:
            course_url = str(request.url_root) + \
                'courses/' + str(course.key.id)
            courses_list.append(course_url)

        user_data["courses"] = courses_list

    if user['role'] == 'student':
        stud_query = client.query(kind='enrollments')
        stud_query.add_filter(filter=PropertyFilter('user_id', '=', user_id))
        enrollments = list(stud_query.fetch())

        enrolled_list = []
        for enrolled in enrollments:
            enrolled_url = str(request.url_root) + \
                'courses/' + str(enrolled["course_id"])
            enrolled_list.append(enrolled_url)
        user_data["courses"] = enrolled_list

    return jsonify(user_data), 200


@app.route('/users/<int:user_id>/avatar', methods=['POST'])
def upload_avatar(user_id):
    """Create or update a user's avatar"""
    if 'file' not in request.files:
        return jsonify(ERROR_400), 400
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return jsonify(ERROR_401), 401

    # verify JWT belongs to the user_id input
    user_key = client.key('users', user_id)
    user = client.get(user_key)
    if not user:
        return jsonify(ERROR_403), 403
    if payload['sub'] != user['sub']:
        return jsonify(ERROR_403), 403

    # Set file_obj to the file sent in the request
    file_obj = request.files['file']
    # If the multipart form data has a part with name 'tag', set the
    # value of the variable 'tag' to the value of 'tag' in the request.
    if 'tag' in request.form:
        tag = request.form['tag']

    # Get a handle on the bucket
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob object for the bucket with the name of the file
    unique_filename = f"{uuid.uuid4()}_{file_obj.filename}"
    blob = bucket.blob(f'avatars/{unique_filename}')
    # Position the file_obj to its beginning
    file_obj.seek(0)
    blob.upload_from_file(file_obj)
    # update user with location of avatar
    user['avatar_location'] = unique_filename
    client.put(user)
    pic_url = str(request.base_url)  # + '/users/' + str(user_id) + '/avatar'
    return ({'avatar_url': pic_url}, 200)


@app.route('/users/<int:user_id>/avatar', methods=['GET'])
def get_avatar(user_id):
    """return the users avatar"""
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return jsonify(ERROR_401), 401

    # verify JWT belongs to the user_id input
    user_key = client.key('users', user_id)
    user = client.get(user_key)
    if not user:
        return jsonify(ERROR_403), 403
    if payload['sub'] != user['sub']:
        return jsonify(ERROR_403), 403

    if 'avatar_location' in user:
        file_name = user['avatar_location']
    else:
        return jsonify(ERROR_404), 404

    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(f'avatars/{file_name}')
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)
    file_obj.seek(0)
    # Send the object as a file in the response with the correct MIME type and file name
    return send_file(file_obj, mimetype='image/png', download_name=file_name)


@app.route('/users/<int:user_id>/avatar', methods=['DELETE'])
def delete_avatar(user_id):
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return jsonify(ERROR_401), 401

    # verify JWT belongs to the user_id input
    user_key = client.key('users', user_id)
    user = client.get(user_key)
    if not user:
        return jsonify(ERROR_403), 403
    if payload['sub'] != user['sub']:
        return jsonify(ERROR_403), 403

    # user doesn't have an avatar
    if 'avatar_location' in user:
        file_name = user['avatar_location']
    else:
        return jsonify(ERROR_404), 404

    # update client info to remove reference to an avatar
    del (user['avatar_location'])
    client.put(user)

    # delete the photo from google storage
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(f'avatars/{file_name}')
    blob.delete()
    return '', 204


@app.route('/courses', methods=['POST'])
def create_course():
    # verify if the request is missing any fields prior to checking the JWT
    content = request.get_json()
    try:
        payload = verify_jwt(request)
        user_sub = payload['sub']
        user_role = payload['nickname']
    except AuthError as e:
        return jsonify(ERROR_401), 401
    if not user_sub:
        return jsonify(ERROR_401), 401
    if user_role != 'admin1':
        return jsonify(ERROR_403), 403

    required_fields = ["subject", "number", "title", "term", "instructor_id"]
    missing_fields = [
        field for field in required_fields if field not in content]
    if missing_fields:
        return jsonify(ERROR_400), 400

    instructor_id = content.get('instructor_id')
    instructor_key = client.key('users', instructor_id)
    instructor = client.get(instructor_key)
    if not instructor or instructor['role'] != 'instructor':
        return jsonify(ERROR_400), 400

    new_course = datastore.entity.Entity(key=client.key('courses'))
    new_course.update({
        "subject": content["subject"],
        "number": content["number"],
        "title": content["title"],
        "term": content["term"],
        "instructor_id": content["instructor_id"]
    })
    client.put(new_course)
    # self and id are not stored in datastore
    new_course["self"] = str(request.base_url) + '/' + str(new_course.key.id)
    new_course["id"] = new_course.key.id
    return (new_course, 201)


@app.route('/courses', methods=['GET'])
def get_courses():
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 3))
    offset = (page - 1) * limit

    query = client.query(kind='courses')
    query.order = ['subject']
    courses = list(query.fetch(offset=offset, limit=limit + 1))

    next_url = None
    if len(courses) > limit:
        next_url = url_for('get_courses', limit=limit, offset=offset + limit)
        courses = courses[:limit]

    courses_data = []
    for course in courses:
        point_self = str(request.base_url) + '/' + str(course.key.id)
        course_data = {
            'id': course.id,
            'subject': course['subject'],
            'number': course['number'],
            'title': course['title'],
            'term': course['term'],
            'instructor_id': course['instructor_id'],
            'self': point_self
        }
        courses_data.append(course_data)

    response_data = {'courses': courses_data}
    if next_url:
        response_data['next'] = str(request.host_url).rstrip('/') + next_url

    return jsonify(response_data)


@app.route('/courses/<int:course_id>', methods=['GET'])
def get_course(course_id):
    course_key = client.key('courses', course_id)
    course = client.get(course_key)

    if not course:
        return jsonify(ERROR_404), 404

    course_data = {
        'id': course.id,
        'subject': course['subject'],
        'number': course['number'],
        'title': course['title'],
        'term': course['term'],
        'instructor_id': course['instructor_id'],
        'self': str(request.base_url)
    }

    return jsonify(course_data), 200


@app.route('/courses/<int:course_id>', methods=['PATCH'])
def update_course(course_id):

    content = request.get_json()
    try:
        payload = verify_jwt(request)
        user_sub = payload['sub']
        user_role = payload['nickname']
    except AuthError as e:
        return jsonify(ERROR_401), 401
    if not user_sub:
        return jsonify(ERROR_401), 401
    if user_role != 'admin1':
        return jsonify(ERROR_403), 403

    # fetch the course
    course_key = client.key('courses', course_id)
    course = client.get(course_key)

    if not course:
        return jsonify(ERROR_404), 404

    if 'instructor_id' in content:
        check_instructor_id = client.key(
            'users', int(content['instructor_id']))
        checked = client.get(check_instructor_id)
        if not checked:
            return jsonify(ERROR_400), 400
    else:
        return jsonify(ERROR_400), 400

    # update whatever is present in the request
    allowed_fields = ["subject", "number", "title", "term", "instructor_id"]
    update_fields = {field: content[field]
                     for field in allowed_fields if field in content}

    course.update(update_fields)
    client.put(course)
    course["self"] = str(request.base_url)
    course["id"] = course.key.id
    return jsonify(course), 200


@app.route('/courses/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):
    try:
        payload = verify_jwt(request)
        user_sub = payload['sub']
        user_role = payload['nickname']
    except AuthError as e:
        return jsonify(ERROR_401), 401
    if not user_sub:
        return jsonify(ERROR_401), 401
    if user_role != 'admin1':
        return jsonify(ERROR_403), 403

    course_key = client.key('courses', course_id)
    course = client.get(course_key)
    if not course:
        return jsonify(ERROR_403), 403

    client.delete(course_key)

    enroll_query = client.query(kind='enrollments')
    enroll_query.add_filter('course_id', '=', course_id)
    enrollments_to_delete = list(enroll_query.fetch())
    for enrollment in enrollments_to_delete:
        client.delete(enrollment.key)
    return '', 204


@app.route('/courses/<int:course_id>/students', methods=['PATCH'])
def update_enrollment(course_id):
    # kind-enrollments, course_id, user_id
    try:
        payload = verify_jwt(request)
        user_role = payload['nickname']
        user_sub = payload['sub']
    except AuthError as e:
        return jsonify(ERROR_401), 401

    if user_role != 'admin1':
        # if not admin then must be the instructor
        query_role = client.query(kind='users')
        query_role.add_filter(filter=PropertyFilter('sub', '=', user_sub))
        query_role.add_filter(filter=PropertyFilter('role', '=', 'instructor'))
        user = list(query_role.fetch())
        if not user:
            # not an instructor
            return jsonify(ERROR_403), 403
        # check if JWT is from instructor of the course
        course_key = client.key('courses', course_id)
        course = client.get(course_key)
        if not course or course['instructor_id'] != user[0].key.id:
            return jsonify(ERROR_403), 403

    content = request.get_json()

    # get the list of student IDs to add and remove
    students_to_add = content['add']
    students_to_remove = content['remove']

    # check for intersection of ids in add/remove
    common_value = set(students_to_add) & set(students_to_remove)
    if common_value:
        return jsonify(ERROR_409), 409

    # ensure values correspond with ID of student
    query_invalid = client.query(kind='users')
    query_invalid.add_filter(filter=PropertyFilter('role', '=', 'student'))
    students = list(query_invalid.fetch())
    student_ids = [student.key.id for student in students]

    all_id = students_to_add + students_to_remove
    invalid_students = [stud for stud in all_id if stud not in student_ids]
    if invalid_students:
        return jsonify(ERROR_409), 409

    # update enrollments based on the provided student IDs
    for student_id in students_to_add:
        query = client.query(kind='enrollments')
        query.add_filter(filter=PropertyFilter('course_id', '=', course_id))
        query.add_filter(filter=PropertyFilter('user_id', '=', student_id))
        existing_enrollment = list(query.fetch())
        if not existing_enrollment:
            # add student to enrollments if not already enrolled
            enrollment = datastore.entity.Entity(key=client.key('enrollments'))
            enrollment.update({
                "course_id": course_id,
                "user_id": student_id
            })
            client.put(enrollment)

    for student_id in students_to_remove:
        # remove student from enrollments if enrolled
        query = client.query(kind='enrollments')
        query.add_filter('course_id', '=', course_id)
        query.add_filter('user_id', '=', student_id)
        enrollments_to_delete = list(query.fetch())
        for enrollment in enrollments_to_delete:
            client.delete(enrollment.key)

    return '', 200


@app.route('/courses/<int:course_id>/students', methods=['GET'])
def get_enrollment(course_id):
    try:
        payload = verify_jwt(request)
        user_sub = payload['sub']
        user_role = payload['nickname']
    except AuthError as e:
        return jsonify(ERROR_401), 401
    if not user_sub:
        return jsonify(ERROR_401), 401

    if user_role != 'admin1':
        # if not admin then must be the instructor
        query_role = client.query(kind='users')
        query_role.add_filter(filter=PropertyFilter('sub', '=', user_sub))
        query_role.add_filter(filter=PropertyFilter('role', '=', 'instructor'))
        user = list(query_role.fetch())
        if not user:
            # not an instructor
            return jsonify(ERROR_403), 403
        # check if JWT is from instructor of the course
        course_key = client.key('courses', course_id)
        course = client.get(course_key)
        if not course or course['instructor_id'] != user[0].key.id:
            return jsonify(ERROR_403), 403

    # fetch the course to check if it exists
    course_key = client.key('courses', course_id)
    course = client.get(course_key)
    if not course:
        return jsonify(ERROR_403), 403

    # query enrollments for the given course_id
    query = client.query(kind='enrollments')
    query.add_filter('course_id', '=', course_id)
    enrollments = list(query.fetch())

    # extract user_ids from the enrollments
    user_ids = [enrollment['user_id'] for enrollment in enrollments]

    return jsonify(user_ids), 200


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
