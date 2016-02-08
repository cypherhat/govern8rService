# govern8r

This is the repo for the govern8r client and server.

## Environment setup

Unfortunately, for right now we need to use python 2.7.11.

Install virtualenv for both client and server. 
```
virtualenv -p <path-to-python-2.7.11> govern8rClient
virtualenv -p <path-to-python-2.7.11> govern8rService
```

## Setup packages for services


In directory govern8rService:
```
	source bin/activate
	sudo pip install flask
	sudo pip install flask-api
	sudo pip install pybitid
	sudo pip install blockcypher
	sudo pip install certifi
	sudo pip install configparser
	sudo pip install ecdsa
	sudo pip install pycrypto
	sudo pip install simple-crypt

```

I've had issues installing a few things due to SSL errors. When I installed pyopenssl, I had such an error. The failure was on the pycparser package. So, my resolution is to clone the repo and install manually.
```
	git clone https://github.com/eliben/pycparser.git
```
	
Change to the pycparser directory and:
```
sudo python ./setup.py install
```
	
Same deal with boto3 - the AWS APIs.
```
	git clone https://github.com/boto/botocore.git
```

Change to the botocore-develop directory
```
sudo python ./setup.py install
```

Now you can:
```
	sudo pip install boto3
	sudo pip install pyopenssl
```	

For the template to start from...
```
	git clone https://github.com/LaurentMT/pybitid_demo.git
```

## AWS setup

Since we are running this stuff in AWS, we should use AWS's dynamoDB since it provisions so easily on AWS. Here are the links:
```
http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Tools.DynamoDBLocal.html#Tools.DynamoDBLocal.DownloadingAndRunning
http://dynamodb-local.s3-website-us-west-2.amazonaws.com/dynamodb_local_latest.zip
```

We also have to install the aws client, to set up the credentials (contact me for these.)

```
	sudo pip install awscli
	sudo pip install awsebcli
```

Before you can connect to the database, you need to configure the credentials using:

```
aws configure
```


## Setup packages for client


in directory govern8rClient:
```
	source bin/activate
	sudo pip install requests
	sudo pip install certifi
	sudo pip install ecdsa
	sudo pip install pycrypto
	sudo pip install configparser
	sudo pip install simple-crypt

```

I've had issues installing a few things due to SSL errors. When I installed pyopenssl, I had such an error. The failure was on the pycparser package. So, my resolution is to clone the repo and install manually.
```
	git clone https://github.com/eliben/pycparser.git
```
	
Change to the pycparser directory and:
```
	sudo python ./setup.py install
	sudo pip install pyopenssl
```


The python-bitcoinlib is a better utility than https://github.com/vbuterin/pybitcointools for some things. However, https://github.com/vbuterin/pybitcointools seems to be the most dominant bitcoin library in python. We need to use both. The problem is that both use the same package name - so they can't be used together. So what I did was forked the project and repackaged with a different name.
```
git clone https://github.com/cypherhat/python-bitcoinlib.git

```

Find the directory where setup.py is (should be python-bitcoinlib). Then set your virtual environment to client, lib, or service (whichever you are working with). And run this to install the package.
```
sudo python setup.py install
```

You should see this package now: python-bitcoinlib (0.5.1-SNAPSHOT)
```
sudo pip list
```

