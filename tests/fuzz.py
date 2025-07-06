import random
import string
import timeit
import requests


def random_str(length=10):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


users = []
tests = 32


def test_user_new():
    fails = 0
    avg_time = 0
    for i in range(tests):
        username = f"user{i}"
        password = random_str()

        start = timeit.default_timer()
        re = requests.post(
            "http://localhost:8080/user/new",
            data={"username": username, "password": password},
        )
        end = timeit.default_timer()
        avg_time += end - start

        if re.status_code != 200:
            fails += 1
        users.append({"username": username, "password": password})

    avg_time /= tests
    avg_time *= 1000
    fail_percentage = tests
    fail_percentage *= (1 / fails) if fails != 0 else 0
    print(
        f"Performed {tests} requests with an average time of {int(avg_time)}ms: {fails} failed. ({fail_percentage})"
    )


def test_repo_new():
    fails = 0
    avg_time = 0
    for user in users:
        start = timeit.default_timer()
        re = requests.post(
            "http://localhost:8080/repo/new",
            auth=requests.auth.HTTPBasicAuth(user["username"], user["password"]),
            data={"test": 69},
        )
        end = timeit.default_timer()
        avg_time += end - start

        if re.status_code != 200:
            fails += 1

    avg_time /= tests
    avg_time *= 1000
    fail_percentage = tests
    fail_percentage *= (1 / fails) if fails != 0 else 0
    print(
        f"Performed {tests} requests with an average time of {int(avg_time)}ms: {fails} failed. ({fail_percentage})"
    )


test_user_new()
test_repo_new()
