# Management Portal

# Installation


## Github

If you do not have a GitHub account sign up for one [here](https://github.com/).

create a new repository using this [guide](https://docs.github.com/en/get-started/quickstart/create-a-repo)

Once you have done this simply add it as a remote

`git remote add <youroriginname> <githuburl>`


## Clone

clone the Payme v2 onto your local machine.

git clone  https://github.com/OrbitLabsDAO/paymev2

then run  the following 2 commands

`npm install --save-dev @11ty/eleventy`

`npm install `

This will set up the Payme v2 locally on your machine.

finally push it to the repo you set up earlier

git push github master


## Cloudflare

If you do not yet have a Cloudflare account please sign up by clicking on this [link](https://dash.cloudflare.com/sign-up?lang=en-US).


Click Pages from the menu on the left. 

![](https://imagedelivery.net/9dYZtR12J2uzlEZe4Joa5w/5c590986-f70c-46d5-7540-46cd284f0d00/public)

Once you are there you can use the following [guide](https://developers.cloudflare.com/pages/get-started/) to connect your git and add the project you just pushed.

Select 11.ty as the framework as shown in the image below

![](https://imagedelivery.net/9dYZtR12J2uzlEZe4Joa5w/77ae9dc2-d46a-4eb6-0480-85be2803b900/public)

then add the ENV vars by going clicking on pages/buildingblocks/settings/environment variables and adding them as shown in the screenshot below

![](https://imagedelivery.net/9dYZtR12J2uzlEZe4Joa5w/ebd4fd7d-6c9b-45ce-e993-63d7ec6c6600/public)



## Wrangler

The next thing you need to do is install Wrangler.  You can find the current documentation for this [here](https://developers.cloudflare.com/workers/wrangler/install-and-update/).

## D1 database
D1 is the Cloudflare database that we are using you can find out more information about it [here](https://developers.cloudflare.com/d1/).


click on workers/d1 and create a new database as shown in the image below

![](https://imagedelivery.net/9dYZtR12J2uzlEZe4Joa5w/4eec15e1-0c5c-4675-5d51-f2b384180c00/public)

then we have to add it to add a D1 database binding called DB and point it to the D1 database you created as shown below 

![](https://imagedelivery.net/9dYZtR12J2uzlEZe4Joa5w/62dc6c22-bddd-402b-8144-53e491a38c00/public)

Now we have to create a wrangler.toml file in the root and add the database name and the id of the database you created in the control panel
note: pages does not use wrangler.toml so I can only assume this is because d1 is in alpha and will be removed soon, regadless the toml file will have the following

[[ d1_databases ]]
binding = "DB" # i.e. available in your Worker on env.DB
database_name = "databasename"
database_id = "databaseid"

The last thing we have to do is run the SQL file to create the tables

sudo npx wrangler d1 execute DB --local  --file=./scripts/sql/schema.sql
sudo wrangler d1 execute DB --file=./scripts/sql/schema.sql

npx wrangler d1 execute DB--local --command="SELECT * FROM user"

## Create environment variables 

We have to rename two files at the root of the project. These files contain the following environment variables.


_.env

_.dev.vars

to 

.env

.dev.vars

Both of these files are the same but for some reason, Cloudflare decided not to use the industry standard .env for their functions so we have to replicate it to get it working locally.  In production, we only have one set of environment variables.

ADMINURL=http://localhost:8789/

The admin URL (the root)

APIURL=http://localhost:8789/api/

The API URL

BEARERTOKEN=

The JWT token to encode with

BLOCKCHAINNETWORK=BNB

The Chain to the user

BLOCKEXPLORER=https://testnet.bscscan.com/

The chains block explorer

CANCREATEACCOUNT=0

Set if you want your users to be able to create accounts or from the admin

CLOUDFLAREURL=

The image upload URL.  Note this is paid service from Cloudflare more information can be found [here](https://www.cloudflare.com/products/cloudflare-images/) 

COMPLEXPASSWORD=0

Set if you want to enforce a complex password or now

CROWDFUNDURL=http://localhost:8788/

The main URL for the crowdfund URL

CRYPTOSALT=fdsfhsjdfhsdufysdufyu8ewyfefwefe

The salt for crypto contracts

EMAILAPIURL=

The email worker, you have to deploy this and it is found in the scripts/workers/email directory [here](https://github.com/OrbitLabsDAO/buildingblocksreporting/tree/master/scripts/workers/email)

FACTORYCONTRACTABI=[{"inputs":[{"internalType":"string","name":"_name","type":"string"},{"internalType":"string","name":"_symbol","type":"string"},{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"bytes32","name":"_salt","type":"bytes32"}],"name":"deploy","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"payable","type":"function"}]
FACTORYCONTRACTADDRESS=0xbf86927f6ce7946608b3e64c91775e4845bc78dd

this is not used yet it currently hard-coded into the web3.js scripts

FORGOTPASSWORDEMAILTEMPLATEID=

the template ID for the forgotten password

NETWORK=testnet

The network to use

PAYMENTLINKTEMPLATEID=

the template ID for the invoice

PAYMEURL=http://localhost:8790/

The URL for the payme application

PAYMEUSERID=1

Your payme user id (1 by default)

PRODUCTNAME=Building Blocks

Name of the product

RPCURL=https://bsc-dataseed.binance.org

the RPC URL for your chosen chain

SECRET=974this is the stupid secret that no one will ever be able to guess344342!

the secret used for hashing

SENDEREMAILNAME=

name that we will send emails 

SIGNUPEMAILTEMPLATEID=

the template ID for signup

## Run it


run the command

`./build.sh

open a browser and go to the following [URL](http://localhost:8789/) and login in with the following details

`test@orbitlabs.xyz`

`test`

You will see 2 properties, these are test properties so you can see the system running. Feel free to delete these if you want.

## cypress testing

It comes with a full test suite that you can access by running the following command 

`./build.sh cypress`


# Production

Pushing the site to production requires a few more steps the first thing you have to do is push the project to your GitHub account if you make any code changes is easy just push 

git push origin master and it will update it on Cloudflare for you 










