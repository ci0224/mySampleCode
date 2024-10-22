import json
import stripe
import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
import os
import pytz
from datetime import datetime
import traceback
from emailer import send_order_confirmation_email, send_failure_email

# variables
global time_reserve_successful
time_reserve_successful = True
global log_stream_url

time_str_format = "%Y-%m-%d %H:%M:%S"
stripe.api_key = os.getenv("STRIPE_API_KEY")
endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
log = logging.getLogger("StripeWebhook")
log.setLevel(logging.INFO)


ddb = boto3.resource("dynamodb")
airyvibeImages = ddb.Table("airyvibeImages")
userDataTable = ddb.Table("UserData")
StudioTable = ddb.Table("Studios")
orderTable = ddb.Table("orderTable")

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


def lambda_handler(event, context):
    # Get the log stream name from the context object
    global log_stream_url
    log_stream_name = context.log_stream_name
    # Construct the CloudWatch Logs console URL
    log_group_name = context.log_group_name
    region = context.invoked_function_arn.split(":")[3]
    log_stream_url = f"https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#logsV2:log-groups/log-group/{log_group_name}/log-events/{log_stream_name}"

    # Log the URL for easy access
    log.info(f"Log Stream URL: {log_stream_url}")
    log.info("event")
    log.info(event)
    path = event.get("path", None)
    if path == "testCompleted":
        handle_checkout_session_completed("20240806_224150_ttestt")
        return
    sig_header = event["sig_header"]
    payload = event["payload"]
    stripe_event = stripe.Webhook.construct_event(
        payload=payload, sig_header=sig_header, secret=endpoint_secret
    )
    log.info('stripe_event["type"]')
    log.info(stripe_event["type"])
    if stripe_event["type"] == "checkout.session.completed":
        session = stripe_event["data"]["object"]
        log.info(session)
        orderID = session.get("metadata", {}).get("orderID", None)
        if orderID is None:
            log.error("Unable to find orderID")
        handle_checkout_session_completed(orderID)
    if stripe_event["type"] == "checkout.session.expired":
        session = stripe_event["data"]["object"]
        log.info(session)
        orderID = session.get("metadata", {}).get("orderID", None)
        if orderID is None:
            log.error("Unable to find orderID")
        handle_checkout_session_expired(orderID)


def handle_checkout_session_expired(orderID):
    order_item = orderTable.query(KeyConditionExpression=Key("orderID").eq(orderID))
    order_item = order_item["Items"][0]
    log.info("item retrive from DB for id" + orderID + ":")
    order_item["status"] = "cancelled"
    orderTable.put_item(Item=order_item)
    return order_item


def handle_checkout_session_completed(orderID: str):
    global time_reserve_successful
    order_item = orderTable.query(KeyConditionExpression=Key("orderID").eq(orderID))
    order_item = order_item["Items"][0]
    log.info("item retrive from DB for id" + orderID + ":")
    log.info(order_item)
    if "charge_id" not in order_item:
        # first time read order_item after paid
        order_item = firstTimeReadOrderAfterPayment(order_item, orderID)
    charge_id = order_item["charge_id"]
    charge = stripe.Charge.retrieve(charge_id)
    log.info("charge" + json.dumps(charge))
    """
    recipients: list[str],
    customer_name: str,
    user_type: Literal["customer", "photographer"],
    package_description: str,
    total_amount_usd: str,
    language: Literal["en", "zh"],
    order_data,
    """
    customer_user_name = order_item["customerUserName"]
    customer_user_data = retrieveUserDataByUserName(customer_user_name)
    customer_name = customer_user_data.get("displayName", customer_user_name)
    customer_email = customer_user_data.get("email", None)
    costomer_language = customer_user_data.get("language", "en")
    service_provider_user_name = order_item["photographerUserName"]
    service_provider_user_data = retrieveUserDataByUserName(service_provider_user_name)
    service_provider_name = service_provider_user_data.get(
        "displayName", service_provider_user_name
    )
    service_provider_email = service_provider_user_data.get("email", None)
    service_provider_email_language = customer_user_data.get("language", "en")
    package_descriptions = ";".join(
        item["description"]
        for prod in order_item["product_list"]
        for item in prod["items"]
    )
    total_amount_usd = str(int(charge["amount"]) / 100)
    if customer_email:
        send_order_confirmation_email(
            [customer_email],
            customer_name,
            "customer",
            package_descriptions,
            total_amount_usd,
            costomer_language,
            order_item,
        )
    else:
        log.error("Customer email is not sent due to email info is missing")
    if service_provider_email:
        send_order_confirmation_email(
            [service_provider_email],
            customer_name,
            "photographer",
            package_descriptions,
            total_amount_usd,
            service_provider_email_language,
            order_item,
        )
    else:
        log.error("Photographer email is not sent due to missing email information")

    if not time_reserve_successful:
        # TODO: add a process to notify both user and photographer to reserve another time.
        #       It would be simple to make a real time reschedule link for user.
        #       And the reschedule will be a resuable, helpful tool in platform
        try:
            global log_stream_url
            studio_name = order_item["studioName"]
            log.info(
                "Reservation failed due to time conflict, sending email to Airy Vibe team"
            )
            subject = "[Urgent][Airyvibe]Failure occurred: Reservation failed due to time conflict"
            content = f"""
            This order reserve time failed due to time conflict! please take a look
            {orderID = }
            {studio_name = }
            {service_provider_email = }
            {log_stream_url = }
            """
            send_failure_email(content, subject)
        except Exception as e:
            log.error("failed to send the failed email")
            traceback.print_exc()
    return charge


def firstTimeReadOrderAfterPayment(order_item, orderID):
    # return updated order_item with 'charge_id' and 'invoice_id'
    global time_reserve_successful
    log.info("checkoutSessionID:" + order_item["checkoutSessionID"])
    checkoutSessionID = order_item["checkoutSessionID"]
    checkoutSession = stripe.checkout.Session.retrieve(checkoutSessionID)
    log.info("checkoutSession:" + json.dumps(checkoutSession))
    invoice_id = checkoutSession["invoice"]
    log.info("invoice_id:" + invoice_id)
    invoice = stripe.Invoice.retrieve(invoice_id)
    log.info("invoice:" + json.dumps(invoice))
    charge_id = invoice["charge"]
    log.info("charge_id:" + charge_id)
    order_item["invoice_id"] = invoice_id
    order_item["charge_id"] = charge_id
    studioName = order_item["studioName"]
    log.info(f"{studioName = }")
    # booking time with studio and update reservation status
    # reservation steps is only required here as we only make reservation once.
    reservation_item = order_item.get("time_reserved", None)
    if reservation_item is not None:
        # we assume the time is in opening time
        # then we only check if the time is booked
        # Booked time: all scheduled time from futrue orders + booked time
        try:
            time_is_available = reserve_is_available_in_studio(
                studioName, reservation_item
            )
            if time_is_available:
                order_item["time_reserved"]["status"] = "reserved"
                log.info("reservation time is set to reserved")
            else:
                order_item["time_reserved"]["status"] = "failed"
                log.info("reservation time is set to reserved")
                time_reserve_successful = False
        except Exception as e:
            traceback.print_exc()
            log.error(f"ERROR, Exception {e} when reserve time in studio")
    orderTable.put_item(Item=order_item)
    # append this order in studio's orders
    linkOrderIdToStudio(studioName, orderID)
    order_item = confirmOrderAfterLinkToStudio(order_item)
    log.info("end of firstTimeReadOrderAfterPayment")
    return order_item


def confirmOrderAfterLinkToStudio(order_item) -> object:
    # return updated order_item with order_id_list removed
    if "waiting_confirmation_from_studio" in order_item:
        # since we add the order in studio, we say that it is confirmed by studio.
        del order_item["waiting_confirmation_from_studio"]
        if order_item["status"] == "unpaid":
            order_item["status"] = "paid"
        orderTable.put_item(Item=order_item)
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


def reserve_is_available_in_studio(studio_name, reserve_item):
    """
    Check if reservation time is available in studio.

    Parameters:
    - studio_name: name of studio
    - reserve_item: reservation data in the order detail

    Returns:
    True if reserve time is available in studio,
    False otherwise.
    """

    studio_orders = getAllStudioOrders(studio_name)
    is_available = True
    for order in studio_orders:
        if "time_reserved" in order:
            if order["time_reserved"] == "reserved":
                if have_time_overlaps(order["time_reserved"], reserve_item):
                    is_available = False

    # TODO: I need to create data schema for the booked time and get
    # them: I will skip this for now and add this step later
    return is_available


def getAllStudioOrders(studio_name):
    studio_item_response = StudioTable.query(
        KeyConditionExpression=Key("studioName").eq(studio_name)
    )
    studioItem = studio_item_response["Items"][0]
    order_id_list = studioItem.get("order_id_list", [])
    return retrieveOrdersByOrderIds(order_id_list)


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
        charge = stripe.Charge.retrieve(charge_id)
        log.info("charge" + json.dumps(charge))
        order_item["charge_item"] = charge
        order_item_list.append(order_item)
    return order_item_list


def isCheckOutSessionPaid(checkout_session_id: str) -> bool:
    """
    @function
    @param {str} checkout session id
    @returns {bool} True==paid, False==unpaid
    """
    checkout_session = stripe.checkout.Session.retrieve(checkout_session_id)
    log.info(f"{checkout_session = }")
    invoice_id = checkout_session["invoice"]
    # if paid -> invoice is not None.
    return invoice_id is not None


def have_time_overlaps(reserve_item_1, reserve_item_2):
    """Determine if two reservation items have time overlaps"""

    start_1 = parse_time(reserve_item_1["time_start"], reserve_item_1["time_zone"])
    end_1 = parse_time(reserve_item_1["time_end"], reserve_item_1["time_zone"])
    start_2 = parse_time(reserve_item_2["time_start"], reserve_item_2["time_zone"])
    end_2 = parse_time(reserve_item_2["time_end"], reserve_item_2["time_zone"])

    return max(start_1, start_2) < min(end_1, end_2)


def parse_time(time_str, time_zone_str):
    """Parse a time string to a timezone-aware datetime object"""
    local_tz = pytz.timezone(time_zone_str)
    naive_dt = datetime.strptime(time_str, time_str_format)
    local_dt = local_tz.localize(naive_dt)
    return local_dt.astimezone(pytz.utc)


def retrieveUserDataByUserName(user_name):
    response = userDataTable.query(KeyConditionExpression=Key("Username").eq(user_name))
    response["Items"] = transform_decimal_to_int(response["Items"])
    if len(response["Items"]) == 0:
        print("ERROR! Failed to find user data in DB.")
        raise Exception("Failed to find user data in DB.")
    return response["Items"][0]
