import json
import time
import urllib.request
import base64
from jose import jwk, jwt
from jose.utils import base64url_decode
import boto3
from boto3.dynamodb.conditions import Key, Attr
import stripe
import os
import copy
from typing import Union

AWS_REGION = "us-west-2"
region = AWS_REGION
USER_POOL_ID = os.getenv("USER_POOL_ID")
userpool_id = USER_POOL_ID
CLIENT_ID = os.getenv("CLIENT_ID")
app_client_id = CLIENT_ID
COGNITO_APP_CLIENT_ID = CLIENT_ID
# Stripe api key
stripe.api_key = os.getenv("STRIPE_API_SECRET_KEY")
# Get the public keys for token verification
keys_url = "https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json".format(
    region, userpool_id
)
with urllib.request.urlopen(keys_url) as f:
    response = f.read()
keys = json.loads(response.decode("utf-8"))["keys"]
# init aws resources
userDataTable = boto3.resource("dynamodb").Table("UserData")
StudioTable = boto3.resource("dynamodb").Table("Studios")
orderTable = boto3.resource("dynamodb").Table("orderTable")
s3 = boto3.client("s3")
imageBucket = "platformuserimages"

hasImage = {"serviceData"}
isImage = {"logo", "cover", "url"}
isPrivateInS3 = []
protectedData = ["studioName", "photographerName", "stripe_account_id", "userType"]


def lambda_handler(event, content):
    print(event)
    """    if event['path'] == 'verifyAccessToken':
        claims = getClaimByVerifyingToken(event['accessToken'])
        # validate claims
        if claims['valid'] is False:
            return {
                'statusCode': 410,
                'body': json.dumps({'error': claims['error']})
            }
        return claims
    Highly doubt this is not in use"""
    if event["path"] == "getUserData":
        try:
            response = getUserData(event)
            print("getUserData end")
            if response["statusCode"] != 200:
                print(json.dumps(response))
            return response
        except Exception as e:
            print("ERROR! In path:", event["path"], str(e))
            return {"statusCode": 521, "body": {"error": str(e)}}

    if event["path"] == "updateUserData":
        try:
            response = updateUserData(event)
            print("updateUserData end")
            if response["statusCode"] != 200:
                print(json.dumps(response))
            return response
        except Exception as e:
            print("ERROR! In path:", event["path"], str(e))
            return {"statusCode": 531, "body": {"error": str(e)}}

    if event["path"] == "setStripeAccount":
        try:
            response = setStripeAccount(event)
            print("setStripeAccount end")
            if response["statusCode"] != 200:
                print(json.dumps(response))
            return response
        except Exception as e:
            print("ERROR! In path:", event["path"], str(e))
            return {"statusCode": 541, "body": {"error": str(e)}}

    if event["path"] == "getUserDataByColumn":
        try:
            response = getUserDataByColumn(event)
            print("getUserDataByColumn end")
            if response["statusCode"] != 200:
                print(json.dumps(response))
            return response
        except Exception as e:
            print("ERROR! In path:", event["path"], str(e))
            return {"statusCode": 551, "body": {"error": str(e)}}

    if event["path"] == "updateUserDataByColumn":
        try:
            response = updateUserDataByColumn(event)
            print("updateUserDataByColumn end")
            if response["statusCode"] != 200:
                print(json.dumps(response))
            return response
        except Exception as e:
            print("ERROR! In path:", event["path"], str(e))
            return {"statusCode": 561, "body": {"error": str(e)}}

    if event["path"] == "updateServiceData":
        try:
            response = updateServiceData(event)
            print("updateServiceData end")
            if response["statusCode"] != 200:
                print(json.dumps(response))
            return response

        except Exception as e:
            print("ERROR! In path:", event["path"], str(e))
            return {"statusCode": 571, "body": {"error": str(e)}}
    if event["path"] == "getAllStudioOrders":
        return getAllStudioOrders(event)
    if event["path"] == "getAllCustomerOrders":
        return getAllCustomerOrders(event)
    if event["path"] == "serviceUpdateSync":
        return serviceUpdateSync(event)

    return {"statusCode": 404, "body": {"error": "Request path not found."}}


def serviceUpdateSync(event):
    """
    This is a path handler
    """
    """
    STEP 1 Verify user's access
    """
    result = getClaimByVerifyingToken(event["accessToken"])
    # validate claim result
    if result["valid"] is False:
        return {"statusCode": 410, "body": json.dumps({"error": result["error"]})}
    username = result["claims"]["username"]
    """
    STEP 2 Confirm there was userData in DB, and load it.
    """
    response = userDataTable.query(KeyConditionExpression=Key("Username").eq(username))
    response["Items"] = transform_decimal_to_int(response["Items"])
    if len(response["Items"]) == 0:
        print("Failed to find user data in DB.")
        print("Aborting")
        return {
            "statusCode": 571,
            "body": json.dumps({"message": "Failed to find user data in DB"}),
        }
    user_data = response["Items"][0]
    updatedServiceData = user_data["serviceData"]
    """
    for new images,
    if it is in s3, delete pendingUpload state,
    else delete the image from service
    """
    for serviceIndex in range(len(updatedServiceData)):
        for imageIndex in range(len(updatedServiceData[serviceIndex]["images"])):
            if updatedServiceData[serviceIndex]["images"][imageIndex].get(
                "pendingUpload", False
            ):
                # this is the image uploaded
                key = updatedServiceData[serviceIndex]["images"][imageIndex]["url"]
                try:
                    s3.head_object(Bucket=imageBucket, Key=key)
                    del updatedServiceData[serviceIndex]["images"][imageIndex][
                        "pendingUpload"
                    ]
                except Exception as e:
                    del updatedServiceData[serviceIndex]["images"][imageIndex]
    user_data["serviceData"] = updatedServiceData
    userDataTable.put_item(Item=user_data)
    return {"statusCode": 200, "body": "Sync done."}


def getUserData(event):
    """
    This is a path handler
    """
    result = getClaimByVerifyingToken(event["accessToken"])
    # validate claim result
    if result["valid"] is False:
        return {"statusCode": 410, "body": json.dumps({"error": result["error"]})}
    username = result["claims"]["username"]
    response = userDataTable.query(KeyConditionExpression=Key("Username").eq(username))
    response["Items"] = transform_decimal_to_int(response["Items"])
    if len(response["Items"]) == 0:
        print("No existing user data in DB. Creating...")
        try:
            response = userDataTable.put_item(
                Item={"Username": username, "dataVersion": 1, "order_id_list": []}
            )
            response["Items"] = [{"Username": username}]
        except Exception as e:
            print(str(e))
            print("Failed to create initial user data.")
            print("Aborting")
            return {
                "statusCode": 521,
                "body": json.dumps(
                    {"error": str(e), "message": "Failed to create initial user data"}
                ),
            }
    user_data_transformed = transform_has_image(response["Items"])
    print("transformed result:", json.dumps(user_data_transformed))
    return {"statusCode": 200, "body": user_data_transformed}


def updateUserData(event):
    """
    This is a path handler
    """
    """
    STEP 1 Verify Request have sufficient to perform update
    """
    try:
        originalUserData = event["originalUserData"]
    except Exception as e:
        errorMessage = "ERROR! Request must have originalUserData."
        print(errorMessage)
        return {"statusCode": 431, "body": json.dumps({"error": errorMessage})}
    try:
        updatedUserData = event["updatedUserData"]
    except Exception as e:
        errorMessage = "ERROR! Request must have updatedUserData."
        print(errorMessage)
        return {"statusCode": 432, "body": json.dumps({"error": errorMessage})}
    """
    STEP 2 Verify user's access
    """
    result = getClaimByVerifyingToken(event["accessToken"])
    # validate claim result
    if result["valid"] is False:
        return {"statusCode": 410, "body": json.dumps({"error": result["error"]})}
    username = result["claims"]["username"]
    """
    STEP 3 Confirm there was userData in DB,
    """
    response = userDataTable.query(KeyConditionExpression=Key("Username").eq(username))
    response["Items"] = transform_decimal_to_int(response["Items"])
    if len(response["Items"]) == 0:
        print("Failed to find user data in DB.")
        print("Aborting")
        return {
            "statusCode": 531,
            "body": json.dumps({"message": "Failed to find user data in DB"}),
        }
    """
    Temperary step to disable image overwrite
    TODO: Disable updateUserData, use update column instead.
    """
    for columnKey in updatedUserData:
        if columnKey in hasImage or columnKey in isImage:
            updatedUserData[columnKey] = response["Items"][0][columnKey]
    """
    STEP 4
        compare originalUserData with data in DB,
        if they are not identical, abort update.
    """

    if response["Items"][0]["dataVersion"] != originalUserData["dataVersion"]:
        return {
            "statusCode": 433,
            "body": json.dumps(
                {
                    "message": "Failed to update due to your data is not up to date. Please retry after refreshing the page."
                }
            ),
        }
    """
    STEP 5 Now we can perform update in DB
    """
    """
    STEP 5.1 There are protected information that must not be modified.
    Note: They can be created for the first time, but not modified after creating.
    """
    for protectedColumn in protectedData:
        if (
            protectedColumn in originalUserData
            and originalUserData[protectedColumn] != updatedUserData[protectedColumn]
        ):
            # if protected data was changed, abort!
            return {
                "statusCode": 532,
                "body": json.dumps(
                    {
                        "error": f"You cannot modified {protectedColumn}.",
                    }
                ),
            }
    # on creating StudioName:
    #   verify uniqueness of studioName and update the studio table
    if "studioName" not in originalUserData and "studioName" in updatedUserData:
        StudiosTable = boto3.resource("dynamodb").Table("Studios")
        studioName = updatedUserData["studioName"]
        try:
            StudiosTableQuery = StudiosTable.query(
                KeyConditionExpression=Key("studioName").eq(studioName)
            )
        except Exception as e:
            print("Abort!")
            print("ERROR!")
            print(str(e))
            return {
                "statusCode": 533,
                "body": json.dumps(
                    {
                        "error": "ERROR! An error occur when confirming the studio name in database.\n"
                        + str(e),
                    }
                ),
            }
        if len(StudiosTableQuery["Items"]) != 0:
            print("Abort!")
            print("This studio name has been taken.\n" + str(studioName))
            return {
                "statusCode": 534,
                "body": json.dumps(
                    {
                        "error": "This studio name has been taken.\n" + str(studioName),
                    }
                ),
            }
        # on creating StudioName, update the studio table
        newStudioItem = {"studioName": studioName, "Username": username}
        try:
            response = StudiosTable.put_item(Item=newStudioItem)
        except Exception as e:
            print("Abort!")
            print("ERROR!")
            print(str(e))
            return {
                "statusCode": 535,
                "body": json.dumps(
                    {
                        "error": "ERROR! An error occur when uploading studio name in database.\n"
                        + str(e),
                    }
                ),
            }
    try:
        updatedUserData["dataVersion"] += 1
        response = userDataTable.put_item(Item=updatedUserData)
    except Exception as e:
        print(str(e))
        print("Error occurs during updating user data in DB.")
        print("Aborting")
        return {
            "statusCode": 536,
            "body": json.dumps(
                {"error": "Error occurs during updating user data in DB.\n" + str(e)}
            ),
        }
    print("Done updateUserData.")
    return {"statusCode": 200, "body": updatedUserData}


def setStripeAccount(event):
    """
    This is a path handler.
    """
    """
    STEP 1 Verify Request have sufficient to perform update
    """
    try:
        accessToken = event["accessToken"]
    except Exception as e:
        errorMessage = "ERROR! Request must have accessToken."
        print(errorMessage)
        return {"statusCode": 441, "body": json.dumps({"error": errorMessage})}
    """
    STEP 2 Verify user's access
    """
    result = getClaimByVerifyingToken(accessToken)
    # validate claim result
    if result["valid"] is False:
        return {"statusCode": 410, "body": json.dumps({"error": result["error"]})}
    username = result["claims"]["username"]
    print("done verifying user, username:")
    print(username)
    """
    STEP 3 Confirm there was userData in DB,
    """
    response = userDataTable.query(KeyConditionExpression=Key("Username").eq(username))
    if len(response["Items"]) == 0:
        print("Failed to find user data in DB.")
        print("Aborting")
        return {
            "statusCode": 531,
            "body": json.dumps({"message": "Failed to find user data in DB"}),
        }
    userData = response["Items"][0]
    """ STEP 4 Create a new Stripe Connect account if there is no account"""
    if "stripe_account_id" not in userData:
        print("Creating a new stripe account for current user")
        account = stripe.Account.create(
            type="standard",
        )
        userData["stripe_account_id"] = str(account.id)
        userData["dataVersion"] += 1
        userDataTable.put_item(Item=userData)
    userStripeAccountID = userData["stripe_account_id"]
    print("userStripeAccountID:")
    print(userStripeAccountID)
    """ STEP 5 Check account status and return to frontend"""
    if "stripe_onboarded" in userData and str(userData["stripe_onboarded"]) == "1":
        # in this case the account is onboarded and no item due on stripe account.
        return {"statusCode": 200, "body": {"status": "onboarded"}}
    userStripeAccount = stripe.Account.retrieve(userStripeAccountID)
    print("userStripeAccount retrieved")
    print(json.dumps(userStripeAccount))
    if (
        userStripeAccount["details_submitted"]
        and userStripeAccount["payouts_enabled"]
        and userStripeAccount["charges_enabled"]
    ):
        # in this case the account is onboarded and no item due on stripe account.
        # we want to also store this status in userData DB
        userData["stripe_onboarded"] = "1"
        userDataTable.put_item(Item=userData)
        return {"statusCode": 200, "body": {"status": "onboarded"}}
    # Create account link for the user to complete Stripe Connect onboarding
    try:
        print("in try create a stripe account link")
        account_link = stripe.AccountLink.create(
            account=userStripeAccountID,
            # refresh_url="http://localhost:3000/linkExpire",  # TODO: Replace with your own URL
            # return_url="http://localhost:3000/profile",  # TODO: Replace with your own URL
            refresh_url="https://www.gloryuniverse.org/linkExpire",
            return_url="https://www.gloryuniverse.org/profile",
            type="account_onboarding",
        )
        print("end try create a stripe account link")
    except Exception as e:
        print("ERROR in trying create a stripe account link")
        print(str(e))

    # Print or return the account link URL, which can be used to onboard the user
    print("Account Link URL:", account_link.url)
    return {
        "statusCode": 200,
        "body": {"status": "onboarding", "url": account_link.url},
    }


def getUserDataByColumn(event):
    """
    This is a path handler
    """
    if "columns" not in event:
        print("columns is missing from the request body.")
        return {
            "statusCode": 451,
            "body": json.dumps({"error": "columns is missing from the request body."}),
        }
    columns = event["columns"]
    result = getClaimByVerifyingToken(event["accessToken"])
    # validate claim result
    if result["valid"] is False:
        print("Token is invalid.")
        print(result["error"])
        return {"statusCode": 452, "body": json.dumps({"error": result["error"]})}
    username = result["claims"]["username"]
    response = userDataTable.query(KeyConditionExpression=Key("Username").eq(username))
    response["Items"] = transform_decimal_to_int(response["Items"])
    if len(response["Items"]) == 0:
        print("User data not found in DB")
        return {"statusCode": 452, "body": json.dumps({"error": result["error"]})}
    userData = response["Items"][0]
    dataCollected = {}
    for column in columns:
        if column in userData:
            # perhaps need to improve this part very seriously
            if column in isImage:
                # not checking for is private since this is user's userdata
                dataCollected[column] = s3.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": imageBucket, "Key": userData[column]},
                    ExpiresIn=3600,
                )
            else:
                dataCollected[column] = userData[column]
    return {"statusCode": 200, "body": dataCollected}


def updateUserDataByColumn(event):
    """
    This is a path handler
    In this path, we did not check for data_version.
    It is a little bit risky
    TODO: improve this whole strategy
    """
    columnToBeUpdated = event["column"]
    columnData = event["columnData"]
    print(f"{columnToBeUpdated=}")
    print(f"{columnData=}")

    result = getClaimByVerifyingToken(event["accessToken"])
    # validate claim result
    if result["valid"] is False:
        return {"statusCode": 410, "body": json.dumps({"error": result["error"]})}
    username = result["claims"]["username"]
    response = userDataTable.query(KeyConditionExpression=Key("Username").eq(username))
    response["Items"] = transform_decimal_to_int(response["Items"])
    userData = response["Items"][0]
    print(f"Found {userData=}")
    if columnToBeUpdated in isImage:
        if "fileType" not in columnData:
            err = 'ERROR! "fileType" is missing from the columnData in request.'
            print(err)
            raise Exception(err)
        if "fileName" not in columnData:
            err = 'ERROR! "fileName" is missing from the columnData in request.'
            print(err)
            raise Exception(err)
        if columnToBeUpdated in userData:
            # check if removal of existing data is needed.
            print(":: I found existing data, I need to do a deletion.")
            print("Deleting existing data in S3...")
            previousDataKey = userData[columnToBeUpdated]
            deleteObject = [{"Key": previousDataKey}]
            response = s3.delete_objects(
                Bucket=imageBucket,
                Delete={
                    "Objects": deleteObject,
                    "Quiet": False,
                },
            )
            print(response)
            print("S3 Images Deletion Done")
        if columnToBeUpdated in isPrivateInS3:
            s3Key = username + "/" + "private" + "/" + columnData["fileName"]
        else:
            s3Key = username + "/" + "public" + "/" + columnData["fileName"]
        userData[columnToBeUpdated] = s3Key
        uploadUrl = s3.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": imageBucket,
                "Key": s3Key,
                "ContentType": columnData["fileType"],
            },
            ExpiresIn=3600,
        )
        response = userDataTable.put_item(Item=userData)
        print("put userdata response: ", response)
    else:
        print("not implemented yet")
        raise Exception("not implemented yet")
    return {
        "statusCode": 200,
        "body": f"dummy success message. target col: {columnToBeUpdated}",
        "nextStep": {"message": "Need to upload image", "uploadUrl": uploadUrl},
    }


def updateServiceData(event):
    """
    This is a path handler
    """
    """
    STEP 1 Verify Request have sufficient to perform update
    """
    must_have = ["updatedServiceData", "dataVersion"]
    for column in must_have:
        if column not in event:
            errorMessage = "ERROR! Request must have " + column + "."
            print(errorMessage)
            return {"statusCode": 471, "body": json.dumps({"error": errorMessage})}
    updatedServiceData = event["updatedServiceData"]
    dataVersion = event["dataVersion"]
    """
    STEP 2 Verify user's access
    """
    result = getClaimByVerifyingToken(event["accessToken"])
    # validate claim result
    if result["valid"] is False:
        return {"statusCode": 410, "body": json.dumps({"error": result["error"]})}
    username = result["claims"]["username"]
    """
    STEP 3 Confirm there was userData in DB,
    """
    response = userDataTable.query(KeyConditionExpression=Key("Username").eq(username))
    response["Items"] = transform_decimal_to_int(response["Items"])
    if len(response["Items"]) == 0:
        print("Failed to find user data in DB.")
        print("Aborting")
        return {
            "statusCode": 571,
            "body": json.dumps({"message": "Failed to find user data in DB"}),
        }
    user_data = response["Items"][0]
    studio_name = user_data["studioName"]
    originalServiceData = user_data["serviceData"]
    """
    STEP 4
        compare originalServiceData with data in DB,
        if they are not identical, abort update.
    """
    if dataVersion != user_data["dataVersion"]:
        return {
            "statusCode": 473,
            "body": json.dumps(
                {
                    "message": "Failed to update due to Data before updating does not match with data in db. Please retry after refreshing the page."
                }
            ),
        }
    """
    STEP 5 Find data_to_add and data_to_remove
    """
    print("Step 5")
    transformed_service_data = []
    id_of_service_to_delete = [s["product_id"] for s in originalServiceData]
    imageKeysToUpload = []

    def needToUploadImage(fileName, key, fileType) -> None:
        # pass it down and call when new images found.
        nonlocal imageKeysToUpload
        imageKeysToUpload.append(
            {"fileName": fileName, "key": key, "fileType": fileType}
        )

    for service in updatedServiceData:
        if "product_id" not in service:
            # new service/product
            transformed_service_data.append(
                handleNewService(
                    service=service,
                    studio_name=studio_name,
                    username=username,
                    needToUploadImage=needToUploadImage,
                )
            )
            continue
        product_id = service["product_id"]
        for original_service_index in range(len(originalServiceData)):
            original_product_id = originalServiceData[original_service_index][
                "product_id"
            ]
            if original_product_id != product_id:
                continue
            original_service = originalServiceData[original_service_index]
            if original_service == service:
                # This service remains unchanged.
                id_of_service_to_delete.remove(product_id)
                transformed_service_data.append(service)
                break
            # This service is changed.
            id_of_service_to_delete.remove(product_id)
            transformed_service = handleServiceModify(
                service=service,
                previous=original_service,
                studio_name=studio_name,
                username=username,
                needToUploadImage=needToUploadImage,
            )
            transformed_service_data.append(transformed_service)
    for service in originalServiceData:
        if service["product_id"] not in id_of_service_to_delete:
            continue
        handleServiceDelete(service, username)
    # STEP 5.1
    # generate upload links for imageKeysToUpload and return to frontend
    imageUploadUrls = dict()
    for image in imageKeysToUpload:
        print(json.dumps(image, indent=2))
        imageUploadUrls[image["fileName"]] = s3.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": imageBucket,
                "Key": image["key"],
                "ContentType": image["fileType"],
            },
            ExpiresIn=3600,
        )
    """
    STEP 6 Now we can perform update in DB
    """
    print("Step 6")
    user_data["serviceData"] = transformed_service_data
    user_data["dataVersion"] += 1
    response = userDataTable.put_item(Item=user_data)
    print("Done updateServiceData.")
    return {
        "statusCode": 200,
        "body": user_data,
        "nextStep": {"message": "Need to upload image", "uploadUrls": imageUploadUrls},
    }


def getAllStudioOrders(event):
    # this is a path handler, return type is list not response object
    result = getClaimByVerifyingToken(event["accessToken"])
    # validate claim result
    if result["valid"] is False:
        return {"statusCode": 410, "body": json.dumps({"error": result["error"]})}
    username = result["claims"]["username"]
    user_data_response = userDataTable.query(
        KeyConditionExpression=Key("Username").eq(username)
    )
    studioName = user_data_response["Items"][0]["studioName"]
    studio_item_response = StudioTable.query(
        KeyConditionExpression=Key("studioName").eq(studioName)
    )
    studioItem = studio_item_response["Items"][0]
    order_id_list = studioItem.get("order_id_list", [])
    return retrieveOrdersByOrderIds(order_id_list)


def getAllCustomerOrders(event):
    # this is a path handler, return type is list not response object
    result = getClaimByVerifyingToken(event["accessToken"])
    # validate claim result
    if result["valid"] is False:
        return {"statusCode": 410, "body": json.dumps({"error": result["error"]})}
    username = result["claims"]["username"]
    user_data_response = userDataTable.query(
        KeyConditionExpression=Key("Username").eq(username)
    )
    user_data = user_data_response["Items"][0]
    order_id_list = user_data.get("order_id_list", [])
    return retrieveOrdersByOrderIds(order_id_list)


################################
######  Helper functions  ######
################################


def retrieveOrdersByOrderIds(order_id_list):
    order_item_list = []
    for order_id in order_id_list:
        order_query_response = orderTable.query(
            KeyConditionExpression=Key("orderID").eq(order_id)
        )
        order_item = order_query_response["Items"][0]
        if order_item["status"] != "unpaid" or isCheckOutSessionPaid(
            order_item["checkoutSessionID"]
        ):
            if "charge_id" not in order_item:
                order_item = firstTimeReadOrderAfterPayment(order_item, order_id)
        charge_id = order_item.get("charge_id", None)
        if charge_id is not None:
            charge = stripe.Charge.retrieve(charge_id)
            order_item["charge_item"] = charge
        order_item_list.append(order_item)
    return order_item_list


def deep_equal(dict1, dict2):
    if type(dict1) != dict or type(dict2) != dict:
        return dict1 == dict2

    if set(dict1.keys()) != set(dict2.keys()):
        return False

    for key in dict1:
        if not deep_equal(dict1[key], dict2[key]):
            return False

    return True


def getClaimByVerifyingToken(token):
    headers = jwt.get_unverified_headers(token)
    kid = headers["kid"]
    message, encoded_signature = str(token).rsplit(".", 1)
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]["kid"]:
            key_index = i
            break
    if key_index == -1:
        error = "Public key not found in jwks.json"
        print(error)
        return {"valid": False, "error": error}
    public_key = jwk.construct(keys[key_index])
    decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        error = "Signature verification failed"
        print(error)
        return {"valid": False, "error": error}
    print("Signature successfully verified")
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    # additionally we can verify the token expiration
    if time.time() > claims["exp"]:
        error = "Token is expired"
        print(error)
        return {"valid": False, "error": error}
    # and the Audience  (use claims['client_id'] if verifying an access token)
    if claims["client_id"] != app_client_id:
        error = "Token was not issued for this audience"
        print(error)
        return {"valid": False, "error": error}
    # now we can use the claims
    print(claims)
    return {"valid": True, "claims": claims}


def getImageUrl(username, path, s3bucket):
    """
    temperary note keeping:
    1. For image item, we will call a function with param(username, path, s3backet)
    to get its link.
    3. Since this will be an internal without auth function, please do not expose it.
    2. Note that it could be a list of items or just a single item.
    """


def move_file_in_s3_bucket(bucket_name, original_key, new_key):
    print(f"Move file in S3: from {original_key} to {new_key}.")
    s3.copy_object(
        Bucket=bucket_name,
        CopySource={"Bucket": bucket_name, "Key": original_key},
        Key=new_key,
    )
    s3.delete_object(Bucket=bucket_name, Key=original_key)


def deleteImageFromS3(key_list, s3bucket):
    deleteObject = [{"Key": key} for key in key_list]
    print(f"Deleting file from S3: {deleteObject = }")
    if len(deleteObject) > 0:
        response = s3.delete_objects(
            Bucket=s3bucket,
            Delete={
                "Objects": deleteObject,
                "Quiet": False,
            },
        )
        print(response)
    print("Images Deletion Done")


def uploadUserImageFromS3(b64image, key, s3bucket):
    """
    upload users image to s3
    """
    b64 = removeBase64Header(b64image)
    imageData = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    response = s3.put_object(
        Body=imageData,
        Bucket=s3bucket,
        Key=key,
    )
    # Check the response for any errors
    if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
        print("S3: successfully upload file(" + key + ").")
        return True
    else:
        print("ERROR: S3: failed to upload file(" + key + ").")
        return False


def removeBase64Header(base64_string):
    # Check if the base64 string is in the "data:" format
    if "data:" in base64_string and ";base64," in base64_string:
        # Break out the header from the base64 content
        header, base64_string = base64_string.split(";base64,")
    return base64_string


def handleServiceDelete(service, username):
    # (1) delete images:
    service_name = service["serviceName"]
    key_to_delete = [
        to_service_s3_key(username, service_name, img["name"])
        for img in service["images"]
    ]
    deleteImageFromS3(key_to_delete, imageBucket)
    # (2) delete prices:
    for p in service["prices"]:
        p_id = p["price_id"]
        stripe.Price.modify(p_id, active=False)
    # (3) delete product
    stripe.Product.modify(service["product_id"], active=False)


def handleServiceModify(
    service, previous, studio_name, username, needToUploadImage: callable
):
    # (1) update Product name
    product_id = service["product_id"]
    service_name = service["serviceName"]
    previous_service_name = previous["serviceName"]
    is_changed_service_name = service_name != previous_service_name
    if is_changed_service_name:
        product_name = studio_name + "-" + service_name
        stripe.Product.modify(product_id, name=product_name)
    # (2) update images
    new_image_names = set()
    for image_index in range(len(service["images"])):
        image = service["images"][image_index]
        file_name = service["images"][image_index]["name"]
        new_image_names.add(file_name)
        # there is two posibility:
        # [1] url = "data:image/png;base64,..." This is new images
        # [2] url = "https://..." This is image unchanged
        # TODO: rewrtie image upload process here and logics to identify new images(by image name? or s3 key?).
        if image["url"][:8] != "https://":
            # new image
            file_type = service["images"][image_index]["fileType"]
            s3Key = to_service_s3_key(username, service_name, file_name)
            needToUploadImage(file_name, s3Key, file_type)
            service["images"][image_index] = {
                "name": file_name,
                "url": s3Key,
                "fileType": file_type,
                "pendingUpload": True,
            }
        elif image["url"][:8] == "https://":
            s3Key = to_service_s3_key(username, service_name, file_name)
            if is_changed_service_name:
                # if service name changed: move file, and update in db accordingly
                previous_s3Key = to_service_s3_key(
                    username, previous_service_name, file_name
                )
                move_file_in_s3_bucket(imageBucket, previous_s3Key, s3Key)
            service["images"][image_index]["url"] = s3Key
        else:
            print("ERROR! in handleServiceModify: (2) updatge images")
            print("service name", service_name)
            print("file name", image["name"])
    name_of_images_to_remove = [
        image["name"]
        for image in previous["images"]
        if image["name"] not in new_image_names
    ]
    key_to_delete = [
        to_service_s3_key(username, service_name, name)
        for name in name_of_images_to_remove
    ]
    deleteImageFromS3(key_to_delete, imageBucket)
    del name_of_images_to_remove, key_to_delete
    # (3) Update prices
    prices = service["prices"]
    previous_prices = previous["prices"]
    transformed_prices = []
    prices_id_to_delete = [p["price_id"] for p in previous_prices]
    for price in prices:
        if "price_id" not in price:
            # new price:
            stripe_price = stripe_price = stripe.Price.create(
                unit_amount=price["price"], currency="usd", product=product_id
            )
            price["price_id"] = stripe_price["id"]
            transformed_prices.append(price)
            continue
        price_id = price["price_id"]
        for previous_price_index in range(len(previous_prices)):
            previous_price_id = previous_prices[previous_price_index]["price_id"]
            if previous_price_id != price_id:
                continue
            previous_price = previous_prices[previous_price_index]
            if price["price"] == previous_price["price"]:
                # The amount of price did not changed:
                prices_id_to_delete.remove(price_id)
                transformed_prices.append(price)
                break
            # This price's amount is changed:
            stripe.Price.modify(price["price_id"], active=False)
            stripe_price = stripe.Price.create(
                unit_amount=price["price"], currency="usd", product=product_id
            )
            prices_id_to_delete.remove(price_id)
            price["price_id"] = stripe_price["id"]
            transformed_prices.append(price)
    for price_id in prices_id_to_delete:
        stripe.Price.modify(price_id, active=False)
    service["prices"] = copy.deepcopy(transformed_prices)
    return service


def handleNewService(service, studio_name, username, needToUploadImage: callable):
    service_name = service["serviceName"]
    # (1)handle images
    # TODO: rewrtie image upload process here and call callable
    for image_index in range(len(service["images"])):
        file_name = service["images"][image_index]["name"]
        file_type = service["images"][image_index]["fileType"]
        s3Key = to_service_s3_key(username, service_name, file_name)
        needToUploadImage(file_name, s3Key, file_type)
        service["images"][image_index] = {
            "name": file_name,
            "url": s3Key,
            "fileType": file_type,
            "pendingUpload": True,
        }
        # previousDataKey = userData[columnToBeUpdated]
        # deleteObject = [{'Key': previousDataKey}]
        # response = s3.delete_objects(
        #     Bucket=imageBucket,
        #     Delete={
        #         'Objects': deleteObject,
        #         'Quiet': False,
        #     },
        # )
        # print(response)
        # print('S3 Images Deletion Done')
    # (2)create product on stripe
    product_name = studio_name + "-" + service["serviceName"]
    stripe_product = stripe.Product.create(name=product_name)
    product_id = stripe_product["id"]
    service["product_id"] = product_id
    prices = service["prices"]
    for price_index in range(len(prices)):
        stripe_price = stripe.Price.create(
            unit_amount=prices[price_index]["price"], currency="usd", product=product_id
        )
        prices[price_index]["price_id"] = stripe_price["id"]
    return service


def to_service_s3_key(username, service_name, file_name):
    return username + "/public/services/" + service_name + "/" + file_name


def transform_has_image(data):
    if isinstance(data, dict):
        for key in data.keys():
            if key in isImage:
                # TODO: handle private when you have private.
                data[key] = s3.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": imageBucket, "Key": data[key]},
                    ExpiresIn=3600,
                )
            elif isinstance(data[key], dict):
                data[key] = transform_has_image(data[key])
            elif isinstance(data[key], list):
                data[key] = transform_has_image(data[key])
    elif isinstance(data, list):
        return [transform_has_image(element) for element in data]
    return data


from decimal import Decimal


def transform_decimal_to_int(obj):
    if isinstance(obj, dict):
        return {key: transform_decimal_to_int(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [transform_decimal_to_int(element) for element in obj]
    elif isinstance(obj, Decimal):
        return int(obj)
    else:
        return obj


def isCheckOutSessionPaid(checkout_session_id: str) -> bool:
    """
    @function
    @param {str} checkout session id
    @returns {bool} True==paid, False==unpaid
    """
    checkout_session = stripe.checkout.Session.retrieve(checkout_session_id)
    print(json.dumps(checkout_session, indent=2))
    invoice_id = checkout_session["invoice"]
    # if paid -> invoice is not None.
    return invoice_id is not None


def firstTimeReadOrderAfterPayment(order_item, orderID):
    # return updated order_item with 'charge_id' and 'invoice_id'
    print("checkoutSessionID:", order_item["checkoutSessionID"])
    checkoutSessionID = order_item["checkoutSessionID"]
    checkoutSession = stripe.checkout.Session.retrieve(checkoutSessionID)
    invoice_id = checkoutSession["invoice"]
    invoice = stripe.Invoice.retrieve(invoice_id)
    charge_id = invoice["charge"]
    order_item["invoice_id"] = invoice_id
    order_item["charge_id"] = charge_id
    studioName = order_item["studioName"]
    orderTable.put_item(Item=order_item)
    # append this order in studio's orders
    linkOrderIdToStudio(studioName, orderID)
    order_item = confirmOrderAfterLinkToStudio(order_item)
    return order_item


def linkOrderIdToStudio(studioName, orderID) -> None:
    studio_query_response = StudioTable.query(
        KeyConditionExpression=Key("studioName").eq(studioName)
    )
    studioItem = studio_query_response["Items"][0]
    if "order_id_list" not in studioItem:
        studioItem["order_id_list"] = []
    if orderID in studioItem["order_id_list"]:
        # already have it, no action needed
        return
    studioItem["order_id_list"].append(orderID)
    StudioTable.put_item(Item=studioItem)


def confirmOrderAfterLinkToStudio(order_item) -> object:
    # return updated order_item with order_id_list removed
    if "waiting_confirmation_from_studio" in order_item:
        # since we add the order in studio, we say that it is confirmed by studio.
        del order_item["waiting_confirmation_from_studio"]
        if order_item["status"] == "unpaid":
            order_item["status"] = "paid"
        orderTable.put_item(Item=order_item)
