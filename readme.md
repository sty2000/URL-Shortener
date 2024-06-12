# Mutiple-User URL Shortener

Our URL Shortener with support for multiple users is a simple yet powerful service designed to create short and manageable links from long URLs. This document outlines the key features, setup instructions, and usage of our service.

## Setup with Source Code

First setup the environment and install flask if applicable. You can choose to activate a virtual environment to handle the packages more conviently.

```
# setup the virtual env
python3 -m venv ./venv
# activate the env in the current terminal
. venv/bin/activate
pip install -r ./requirements.txt
```
## Setup with Docker
### Pull the image
```
docker pull cedar3/webassn2:group16
```
### run the server with 5000 export
```
docker run -p 5000:5000 webassn2:group16
```
If you want to change the export port, just run 
```
docker run -p 5000:<port_num> webassn2:group16
```

## Run the server

You can choose to run the program using the following command:

```
$ cd <Your_path>
$ $env:FLASK_APP='api'
$ venv\Scripts\activate
# You will find the '(venv)' ahead of the prompt
$ flask run (--port portnum)
# The server will automatically run at http://127.0.0.1:5000, or specifying another port
$ python3 -m flask run (--port portnum) 
```

Apart from that, you can also turn on the 'debug' mode by running

```
python api.py
```

This because we turn on the 'debug' mode using the following code

```Python
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
```

### Specifications of APIs

| APIs for URL shortening | #Respond1 | #Respond2 | #Respond3 | #Respond4 |
| --- | --- | --- | --- | --- |
| /:id - GET | 301, value | 404 |     |     |
| /:id - PUT | 200 | 400, "error" | 404 | 403,“forbidden” |
| /:id - DELETE | 200 | 400, "error" | 404 | 403,“forbidden” |
| / - GET | 200, ids |     |     | 403,“forbidden” |
| / - POST | 201, id | 400, "error" |     | 403,“forbidden” |
| / - DELETE | 404 |     |     | 403,“forbidden” |

| APIs for multiple user authentication | #Respond1 | #Respond2 |
| --- | --- | --- |
| /users - POST | 201 | 409, “duplicate” |
| /users - PUT | 200 | 403, “forbidden” |
| /users/login - POST | 200, JWT | 403, “forbidden” |

## Example usage of the Service via curl

For all ids stored in the server (/ - GET):

```
curl  http://127.0.0.1:5000/ 
```

## Example usage of the service via Postman

We recommend you to use the VSCode IDE and install the Postman plugin.
After installation, please establish a new HTTP request to the localhost URL `http://127.0.0.1:5000`.
Then, you can feel free to use the POST, GET, PUT, DELETE methods provided by Postman. For example, you can use the POST method by adding the following JSON text into the Body section:

```json
{
    "url": "https://example.com"
}
```

As for CRUD by ID operations, please don't forget to add the ID (`0a`, etc.) to the localhost URL's path.


## Usage with Kubernetes
In Assignment 3, we have added a persistent volume to our docker and deployed our services to Kubernetes to enhance functionality. The following sections describe how you can make use of them.

### new Docker
You can acquire the new Docker versions via the following commands:
```
docker pull cedar3/webassn3:local    # to run docker locally
docker pull cedar3/webassn3:group16    # to run docker on Kubernetes
```
To run the Docker service, please use:
```
 docker run -p 5000:5000 -v <volume mount path>:/app/nfs/share cedar3/webassn3:local
```
You can decide which directory you want to mount, as any files changed in the host directory will be reflected inside the container, and vice versa. This is used for persistent storage and for live-editing code that's running inside the container.

To automatically define and activate the volume service, please use:
```
docker compose up -d
```
### K8s Commands
The following shows some frequent commands for Kubernetes that are primarily used for deploying and managing Kubernetes resources:

1. `kubectl apply -f <filename>`.
   This command is used to create or update resources defined in the specified file. You can run the following commands to deploy the StatefulSet and Service resources respectively:
   ```
   kubectl apply -f webapp-statefulset.yaml
   kubectl apply -f webapp-service.yaml
   ```
2. `watch kubectl get <component>`. To check if all components are ready, you can use the following:
   ```
   watch kubectl get nodes
   watch kubectl get -A pods
   ```

3. `kubectl get <resource>`.
   This command is to list all instances of a type of resource. For example, to get a list of Services, you can use:
   ```
   kubectl get services
   ```
   As for StatefulSets, you can use:
   ```
   kubectl get statefulsets
   ```

4. `kubectl describe <resource> <name>`:
   This command provides detailed information about a specific resource. For example:
   ```
   kubectl describe statefulset webapp-statefulset
   kubectl describe service webapp-service
   ```

5. `kubectl delete -f <filename>`:
   If you need to delete the resources defined in the file, you can use this command:
   ```
   kubectl delete -f webapp-statefulset.yaml
   kubectl delete -f webapp-service.yaml
   ```

6. `kubectl exec -it <pod-name> -- /bin/bash`:
   This command is used to open an interactive terminal in a running Pod. For example, you can use the following command to eenter the docker container of `node 0`:
   ```
   kubectl exec -it webapp-statefulset-0 -- /bin/bash
   ```

### External Accessibility
Our services are also publicly available with the deployment running on cluster. You can access this portal `http://145.100.135.146:30001` instead of the local `5000` port and make use of the 2 types of APIs mentioned before.
   

### Reference

1. Regular expression: https://stackoverflow.com/questions/3809401/what-is-a-good-regular-expression-to-match-a-url
  
2. Fetching the client ip address with reference at: https://stackoverflow.com/questions/3759981/get-ip-address-of-visitors-using-flask-for-python
  
3. Using SQLAlchemy: https://python-adv-web-apps.readthedocs.io/en/latest/flask_db1.html
  
4. Tutorial of Flask Database: https://tutorial.helloflask.com/database/
  
5. Base64: https://docs.python.org/3/library/base64.html
  
6. Json: https://docs.python.org/3/library/json.html
  
7. hmac: https://docs.python.org/3/library/hmac.html
  
8. Using secrets library to generate random keys: https://docs.python.org/3/library/secrets.html#module-secrets
  
9. Decoding JSON Headers: https://blog.csdn.net/LC_Liangchao/article/details/122041219



