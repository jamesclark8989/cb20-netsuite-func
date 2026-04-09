import os
import time
import hmac
import hashlib
import base64
import urllib.parse
import secrets
import requests
import pyodbc
from dotenv import load_dotenv

load_dotenv()

# NetSuite credentials
ACCOUNT_ID = os.environ.get("NETSUITE_ACCOUNT_ID")
CONSUMER_KEY = os.environ.get("NETSUITE_CONSUMER_KEY")
CONSUMER_SECRET = os.environ.get("NETSUITE_CONSUMER_SECRET")
TOKEN_ID = os.environ.get("NETSUITE_TOKEN_ID")
TOKEN_SECRET = os.environ.get("NETSUITE_TOKEN_SECRET")

# SQL credentials
SQL_SERVER = os.environ.get("SQL_SERVER")
SQL_DATABASE = os.environ.get("SQL_DATABASE")
SQL_USERNAME = os.environ.get("SQL_USERNAME")
SQL_PASSWORD = os.environ.get("SQL_PASSWORD")

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def safe_decimal(value):
    if value is None or value == '' or value == 'F' or value == 'T':
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None

def safe_int(value):
    if value is None or value == '':
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None

def safe_str(value, max_len=None):
    if value is None:
        return None
    s = str(value)
    if max_len is not None:
        return s[:max_len]
    return s

def safe_bool(value):
    if value is None:
        return None
    return 1 if str(value).upper() == 'T' else 0

# ---------------------------------------------------------------------------
# Connection / Auth
# ---------------------------------------------------------------------------

def get_sql_connection():
    conn_str = (
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={SQL_SERVER};"
        f"DATABASE={SQL_DATABASE};"
        f"UID={SQL_USERNAME};"
        f"PWD={SQL_PASSWORD};"
    )
    return pyodbc.connect(conn_str)

def generate_tba_header(method, url, params=None):
    oauth_nonce = secrets.token_hex(16)
    oauth_timestamp = str(int(time.time()))
    oauth_params = {
        "oauth_consumer_key": CONSUMER_KEY,
        "oauth_nonce": oauth_nonce,
        "oauth_signature_method": "HMAC-SHA256",
        "oauth_timestamp": oauth_timestamp,
        "oauth_token": TOKEN_ID,
        "oauth_version": "1.0",
    }
    all_params = {**oauth_params, **(params or {})}
    sorted_params = sorted(all_params.items())
    encoded_params = urllib.parse.urlencode(sorted_params)
    base_string = "&".join([
        method.upper(),
        urllib.parse.quote(url, safe=""),
        urllib.parse.quote(encoded_params, safe="")
    ])
    signing_key = f"{urllib.parse.quote(CONSUMER_SECRET, safe='')}&{urllib.parse.quote(TOKEN_SECRET, safe='')}"
    signature = base64.b64encode(
        hmac.new(signing_key.encode(), base_string.encode(), hashlib.sha256).digest()
    ).decode()
    oauth_params["oauth_signature"] = signature
    realm = ACCOUNT_ID.replace("-", "_").upper()
    auth_header = "OAuth realm=\"" + realm + "\", " + ", ".join(
        f'{k}="{urllib.parse.quote(str(v), safe="")}"' for k, v in sorted(oauth_params.items())
    )
    return auth_header

def run_suiteql(query, limit=1000, offset=0):
    base_url = f"https://{ACCOUNT_ID}.suitetalk.api.netsuite.com/services/rest/query/v1/suiteql"
    query_params = {"limit": str(limit), "offset": str(offset)}
    auth_header = generate_tba_header("POST", base_url, query_params)
    url = f"{base_url}?limit={limit}&offset={offset}"
    headers = {
        "Authorization": auth_header,
        "Content-Type": "application/json",
        "Prefer": "transient"
    }
    response = requests.post(url, headers=headers, json={"q": query})
    response.raise_for_status()
    return response.json()

def extract_all(query, page_size=1000):
    all_items = []
    offset = 0
    while True:
        result = run_suiteql(query, limit=page_size, offset=offset)
        items = result.get("items", [])
        # Normalize all keys to lowercase to avoid case-sensitivity issues
        items = [{k.lower(): v for k, v in row.items()} for row in items]
        all_items.extend(items)
        print(f"  Fetched {len(all_items)} records so far...")
        if not result.get("hasMore", False):
            break
        offset += page_size
    return all_items

# ---------------------------------------------------------------------------
# Load functions — each INSERT matches DDL column list exactly
# ---------------------------------------------------------------------------

def load_customers(conn):
    print("Loading CustomerDim...")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM CustomerDim")

    items = extract_all("""
        SELECT id, entityId, companyName, altName, externalId, searchStage,
               entityStatus, isInactive, isPerson, salesRep, terms, currency,
               phone, dateCreated, lastModifiedDate
        FROM customer
    """)

    skipped = 0
    for row in items:
        if not row.get('id'):
            print(f"  SKIP customer row — missing id: {row}")
            skipped += 1
            continue
        cursor.execute("""
            INSERT INTO CustomerDim (
                NetSuiteID, EntityID, CompanyName, AltName, ExternalID,
                Stage, EntityStatus, IsInactive, IsPerson, SalesRepID,
                Terms, Currency, Phone, DateCreated, LastModifiedDate
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        row.get('id'),
        row.get('entityid'),
        safe_str(row.get('companyname'), 255),
        safe_str(row.get('altname'), 255),
        row.get('externalid'),
        row.get('searchstage'),
        row.get('entitystatus'),
        safe_bool(row.get('isinactive')),
        safe_bool(row.get('isperson')),
        row.get('salesrep'),
        row.get('terms'),
        row.get('currency'),
        safe_str(row.get('phone'), 50),
        row.get('datecreated'),
        row.get('lastmodifieddate'))

    conn.commit()
    print(f"  Loaded {len(items) - skipped} customers ({skipped} skipped)")


def load_vendors(conn):
    print("Loading VendorDim...")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM VendorDim")

    items = extract_all("""
        SELECT id, entityId, companyName, altName, externalId, accountNumber,
               currency, terms, creditLimit, isInactive, isPerson,
               phone, email, dateCreated, lastModifiedDate
        FROM vendor
    """)

    skipped = 0
    for row in items:
        if not row.get('id'):
            print(f"  SKIP vendor row — missing id: {row}")
            skipped += 1
            continue
        cursor.execute("""
            INSERT INTO VendorDim (
                NetSuiteID, EntityID, CompanyName, AltName, ExternalID,
                AccountNumber, Currency, Terms, CreditLimit, IsInactive,
                IsPerson, Phone, Email, DateCreated, LastModifiedDate
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        row.get('id'),
        row.get('entityid'),
        safe_str(row.get('companyname'), 255),
        safe_str(row.get('altname'), 255),
        row.get('externalid'),
        row.get('accountnumber'),
        row.get('currency'),
        row.get('terms'),
        safe_decimal(row.get('creditlimit')),
        safe_bool(row.get('isinactive')),
        safe_bool(row.get('isperson')),
        safe_str(row.get('phone'), 50),
        safe_str(row.get('email'), 255),
        row.get('datecreated'),
        row.get('lastmodifieddate'))

    conn.commit()
    print(f"  Loaded {len(items) - skipped} vendors ({skipped} skipped)")


def load_items(conn):
    print("Loading ItemDim...")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ItemDim")

    items = extract_all("""
        SELECT id, itemId, displayName, description,
               itemType, isInactive, cost, lastModifiedDate
        FROM item
    """)

    skipped = 0
    for row in items:
        if not row.get('id'):
            print(f"  SKIP item row — missing id: {row}")
            skipped += 1
            continue
        cursor.execute("""
            INSERT INTO ItemDim (
                NetSuiteID, ItemID, DisplayName, Description,
                ItemType, IsInactive, UnitCost, SalePrice, LoadedAt
            ) VALUES (?,?,?,?,?,?,?,?,GETDATE())
        """,
        row.get('id'),
        safe_str(row.get('itemid'), 500),
        safe_str(row.get('displayname'), 255),
        safe_str(row.get('description')),
        row.get('itemtype'),
        safe_bool(row.get('isinactive')),
        safe_decimal(row.get('cost')),
        None)

    conn.commit()
    print(f"  Loaded {len(items) - skipped} items ({skipped} skipped)")


def load_sales_orders(conn):
    print("Loading SalesOrder_Header...")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM SalesOrder_Header")
    cursor.execute("DELETE FROM SalesOrder_Detail")

    headers = extract_all("""
        SELECT id, tranId, transactionNumber, externalId, entity, salesRep,
               tranDate, shipDate, actualShipDate, status, total, taxTotal,
               estGrossProfit, estGrossProfitPercent, terms, memo, shipAddress,
               source, currency, subsidiary, voided, createdDate, lastModifiedDate
        FROM salesOrder
    """)

    skipped = 0
    for row in headers:
        if not row.get('id'):
            print(f"  SKIP sales order header — missing id: {row}")
            skipped += 1
            continue
        cursor.execute("""
            INSERT INTO SalesOrder_Header (
                NetSuiteID, TranID, TransactionNumber, ExternalID, CustomerID,
                SalesRepID, TranDate, ShipDate, ActualShipDate, Status,
                Total, TaxTotal, EstGrossProfit, EstGrossProfitPct, Terms,
                Memo, ShipAddress, Source, Currency, Subsidiary, Voided,
                CreatedDate, LastModifiedDate
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        row.get('id'), row.get('tranid'), row.get('transactionnumber'),
        row.get('externalid'), row.get('entity'), row.get('salesrep'),
        row.get('trandate'), row.get('shipdate'), row.get('actualshipdate'),
        row.get('status'),
        safe_decimal(row.get('total')), safe_decimal(row.get('taxtotal')),
        safe_decimal(row.get('estgrossprofit')),
        safe_decimal(row.get('estgrossprofitpercent')),
        row.get('terms'),
        safe_str(row.get('memo')),
        safe_str(row.get('shipaddress')),
        row.get('source'), row.get('currency'), row.get('subsidiary'),
        safe_bool(row.get('voided')),
        row.get('createddate'), row.get('lastmodifieddate'))

    conn.commit()
    print(f"  Loaded {len(headers) - skipped} sales order headers ({skipped} skipped)")

    print("Loading SalesOrder_Detail...")
    details = extract_all("""
        SELECT salesOrder, line, item, itemType, description, quantity, amount,
               grossAmt, estGrossProfit, estGrossProfitPercent, costEstimate,
               taxRate1, tax1Amt, quantityFulfilled, quantityBilled,
               isClosed, isTaxable, class, department, location
        FROM salesOrderItem
    """)

    skipped = 0
    for row in details:
        if not row.get('salesorder'):
            print(f"  SKIP detail row — missing salesorder FK: {row}")
            skipped += 1
            continue
        cursor.execute("""
            INSERT INTO SalesOrder_Detail (
                SalesOrderID, Line, ItemID, ItemType, Description, Quantity,
                Amount, GrossAmt, EstGrossProfit, EstGrossProfitPct, CostEstimate,
                TaxRate1, Tax1Amt, QuantityFulfilled, QuantityBilled,
                IsClosed, IsTaxable, Class, Department, Location
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        row.get('salesorder'), safe_int(row.get('line')), row.get('item'),
        row.get('itemtype'),
        safe_str(row.get('description')),
        safe_decimal(row.get('quantity')), safe_decimal(row.get('amount')),
        safe_decimal(row.get('grossamt')), safe_decimal(row.get('estgrossprofit')),
        safe_decimal(row.get('estgrossprofitpercent')),
        safe_decimal(row.get('costestimate')),
        safe_decimal(row.get('taxrate1')), safe_decimal(row.get('tax1amt')),
        safe_decimal(row.get('quantityfulfilled')),
        safe_decimal(row.get('quantitybilled')),
        safe_bool(row.get('isclosed')),
        safe_bool(row.get('istaxable')),
        row.get('class'), row.get('department'), row.get('location'))

    conn.commit()
    print(f"  Loaded {len(details) - skipped} sales order detail lines ({skipped} skipped)")


def load_purchase_orders(conn):
    print("Loading PurchaseOrder_Header...")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM PurchaseOrder_Header")
    cursor.execute("DELETE FROM PurchaseOrder_Detail")

    headers = extract_all("""
        SELECT id, tranId, transactionNumber, externalId, entity, tranDate,
               dueDate, status, total, taxTotal, terms, memo, currency,
               subsidiary, voided, createdDate, lastModifiedDate
        FROM purchaseOrder
    """)

    skipped = 0
    for row in headers:
        if not row.get('id'):
            print(f"  SKIP purchase order header — missing id: {row}")
            skipped += 1
            continue
        cursor.execute("""
            INSERT INTO PurchaseOrder_Header (
                NetSuiteID, TranID, TransactionNumber, ExternalID, VendorID,
                TranDate, DueDate, Status, Total, TaxTotal, Terms, Memo,
                Currency, Subsidiary, Voided, CreatedDate, LastModifiedDate
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        row.get('id'), row.get('tranid'), row.get('transactionnumber'),
        row.get('externalid'), row.get('entity'),
        row.get('trandate'), row.get('duedate'), row.get('status'),
        safe_decimal(row.get('total')), safe_decimal(row.get('taxtotal')),
        row.get('terms'),
        safe_str(row.get('memo')),
        row.get('currency'), row.get('subsidiary'),
        safe_bool(row.get('voided')),
        row.get('createddate'), row.get('lastmodifieddate'))

    conn.commit()
    print(f"  Loaded {len(headers) - skipped} purchase order headers ({skipped} skipped)")

    print("Loading PurchaseOrder_Detail...")
    details = extract_all("""
        SELECT purchaseOrder, line, item, itemType, description, quantity,
               amount, rate, quantityReceived, quantityBilled,
               isClosed, isBillable, class, department, location
        FROM purchaseOrderItem
    """)

    skipped = 0
    for row in details:
        if not row.get('purchaseorder'):
            print(f"  SKIP PO detail row — missing purchaseorder FK: {row}")
            skipped += 1
            continue
        cursor.execute("""
            INSERT INTO PurchaseOrder_Detail (
                PurchaseOrderID, Line, ItemID, ItemType, Description, Quantity,
                Amount, Rate, QuantityReceived, QuantityBilled,
                IsClosed, IsBillable, Class, Department, Location
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        row.get('purchaseorder'), safe_int(row.get('line')), row.get('item'),
        row.get('itemtype'),
        safe_str(row.get('description')),
        safe_decimal(row.get('quantity')), safe_decimal(row.get('amount')),
        safe_decimal(row.get('rate')),
        safe_decimal(row.get('quantityreceived')),
        safe_decimal(row.get('quantitybilled')),
        safe_bool(row.get('isclosed')),
        safe_bool(row.get('isbillable')),
        row.get('class'), row.get('department'), row.get('location'))

    conn.commit()
    print(f"  Loaded {len(details) - skipped} purchase order detail lines ({skipped} skipped)")


def load_sales_order_fulfillments(conn):
    print("Loading SalesOrderFulfillment_Header...")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM SalesOrderFulfillment_Header")
    cursor.execute("DELETE FROM SalesOrderFulfillment_Detail")

    headers = extract_all("""
        SELECT id, tranId, transactionNumber, createdFrom,
               entity, tranDate, status, shipAddress,
               memo, createdDate, lastModifiedDate
        FROM itemFulfillment
    """)

    skipped = 0
    for row in headers:
        if not row.get('id'):
            print(f"  SKIP fulfillment header — missing id: {row}")
            skipped += 1
            continue
        cursor.execute("""
            INSERT INTO SalesOrderFulfillment_Header (
                NetSuiteID, TranID, TransactionNumber,
                SalesOrderID, CustomerID, TranDate, ShipDate, Status,
                ShipAddress, Memo, CreatedDate, LastModifiedDate
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        row.get('id'), row.get('tranid'), row.get('transactionnumber'),
        row.get('createdfrom'),
        row.get('entity'), row.get('trandate'),
        None,               # ShipDate — no corresponding field in itemFulfillment
        row.get('status'),
        safe_str(row.get('shipaddress')),
        safe_str(row.get('memo')),
        row.get('createddate'), row.get('lastmodifieddate'))

    conn.commit()
    print(f"  Loaded {len(headers) - skipped} fulfillment headers ({skipped} skipped)")

    print("Loading SalesOrderFulfillment_Detail...")
    details = extract_all("""
        SELECT itemFulfillment, line, item, description,
               quantity, location
        FROM itemFulfillmentItem
    """)

    skipped = 0
    for row in details:
        if not row.get('itemfulfillment'):
            print(f"  SKIP fulfillment detail row — missing itemfulfillment FK: {row}")
            skipped += 1
            continue
        cursor.execute("""
            INSERT INTO SalesOrderFulfillment_Detail (
                FulfillmentID, Line, ItemID, Description,
                Quantity, QuantityRemaining, Location
            ) VALUES (?,?,?,?,?,?,?)
        """,
        row.get('itemfulfillment'), safe_int(row.get('line')),
        row.get('item'),
        safe_str(row.get('description')),
        safe_decimal(row.get('quantity')),
        None,               # QuantityRemaining — not available in itemFulfillmentItem
        row.get('location'))

    conn.commit()
    print(f"  Loaded {len(details) - skipped} fulfillment detail lines ({skipped} skipped)")


def load_sales_order_invoices(conn):
    print("Loading SalesOrderInvoice_Header...")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM SalesOrderInvoice_Header")
    cursor.execute("DELETE FROM SalesOrderInvoice_Detail")

    headers = extract_all("""
        SELECT id, tranId, transactionNumber, createdFrom,
               entity, tranDate, dueDate, status,
               total, taxTotal, amountPaid, amountRemaining,
               terms, memo, currency, voided,
               createdDate, lastModifiedDate
        FROM invoice
    """)

    skipped = 0
    for row in headers:
        if not row.get('id'):
            print(f"  SKIP invoice header — missing id: {row}")
            skipped += 1
            continue
        cursor.execute("""
            INSERT INTO SalesOrderInvoice_Header (
                NetSuiteID, TranID, TransactionNumber, SalesOrderID,
                CustomerID, TranDate, DueDate, Status,
                Total, TaxTotal, AmountDue, AmountPaid,
                Terms, Memo, Currency, Voided,
                CreatedDate, LastModifiedDate
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        row.get('id'), row.get('tranid'), row.get('transactionnumber'),
        row.get('createdfrom'),
        row.get('entity'), row.get('trandate'), row.get('duedate'),
        row.get('status'),
        safe_decimal(row.get('total')), safe_decimal(row.get('taxtotal')),
        safe_decimal(row.get('amountremaining')),
        safe_decimal(row.get('amountpaid')),
        row.get('terms'),
        safe_str(row.get('memo')),
        row.get('currency'),
        safe_bool(row.get('voided')),
        row.get('createddate'), row.get('lastmodifieddate'))

    conn.commit()
    print(f"  Loaded {len(headers) - skipped} invoice headers ({skipped} skipped)")

    print("Loading SalesOrderInvoice_Detail...")
    details = extract_all("""
        SELECT invoice, line, item, description, quantity,
               amount, rate, tax1Amt, taxRate1,
               class, department
        FROM invoiceItem
    """)

    skipped = 0
    for row in details:
        if not row.get('invoice'):
            print(f"  SKIP invoice detail row — missing invoice FK: {row}")
            skipped += 1
            continue
        cursor.execute("""
            INSERT INTO SalesOrderInvoice_Detail (
                InvoiceID, Line, ItemID, Description, Quantity,
                Amount, Rate, TaxRate1, Tax1Amt,
                Class, Department
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """,
        row.get('invoice'), safe_int(row.get('line')),
        row.get('item'),
        safe_str(row.get('description')),
        safe_decimal(row.get('quantity')), safe_decimal(row.get('amount')),
        safe_decimal(row.get('rate')),
        safe_decimal(row.get('taxrate1')), safe_decimal(row.get('tax1amt')),
        row.get('class'), row.get('department'))

    conn.commit()
    print(f"  Loaded {len(details) - skipped} invoice detail lines ({skipped} skipped)")


def load_purchase_order_receipts(conn):
    print("Loading PurchaseOrderReceipt_Header...")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM PurchaseOrderReceipt_Header")
    cursor.execute("DELETE FROM PurchaseOrderReceipt_Detail")

    headers = extract_all("""
        SELECT id, tranId, transactionNumber, createdFrom,
               entity, tranDate, memo,
               createdDate, lastModifiedDate
        FROM itemReceipt
    """)

    skipped = 0
    for row in headers:
        if not row.get('id'):
            print(f"  SKIP receipt header — missing id: {row}")
            skipped += 1
            continue
        cursor.execute("""
            INSERT INTO PurchaseOrderReceipt_Header (
                NetSuiteID, TranID, TransactionNumber, PurchaseOrderID,
                VendorID, TranDate, Memo, CreatedDate, LastModifiedDate
            ) VALUES (?,?,?,?,?,?,?,?,?)
        """,
        row.get('id'), row.get('tranid'), row.get('transactionnumber'),
        row.get('createdfrom'),
        row.get('entity'), row.get('trandate'),
        safe_str(row.get('memo')),
        row.get('createddate'), row.get('lastmodifieddate'))

    conn.commit()
    print(f"  Loaded {len(headers) - skipped} receipt headers ({skipped} skipped)")

    print("Loading PurchaseOrderReceipt_Detail...")
    details = extract_all("""
        SELECT itemReceipt, line, item, description,
               quantity, rate, amount, location
        FROM ItemReceiptItem
    """)

    skipped = 0
    for row in details:
        if not row.get('itemreceipt'):
            print(f"  SKIP receipt detail row — missing itemreceipt FK: {row}")
            skipped += 1
            continue
        cursor.execute("""
            INSERT INTO PurchaseOrderReceipt_Detail (
                ReceiptID, Line, ItemID, Description,
                Quantity, Rate, Amount, Location
            ) VALUES (?,?,?,?,?,?,?,?)
        """,
        row.get('itemreceipt'), safe_int(row.get('line')),
        row.get('item'),
        safe_str(row.get('description')),
        safe_decimal(row.get('quantity')),
        safe_decimal(row.get('rate')),
        safe_decimal(row.get('amount')),
        row.get('location'))

    conn.commit()
    print(f"  Loaded {len(details) - skipped} receipt detail lines ({skipped} skipped)")


def load_purchase_order_vendor_bills(conn):
    print("Loading PurchaseOrderVendorBill_Header...")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM PurchaseOrderVendorBill_Header")
    cursor.execute("DELETE FROM PurchaseOrderVendorBill_Detail")

    headers = extract_all("""
        SELECT id, tranId, transactionNumber, createdFrom,
               entity, tranDate, dueDate, status,
               total, taxTotal, amountPaid, amountRemaining,
               terms, memo, currency, voided,
               createdDate, lastModifiedDate
        FROM vendorBill
    """)

    skipped = 0
    for row in headers:
        if not row.get('id'):
            print(f"  SKIP vendor bill header — missing id: {row}")
            skipped += 1
            continue
        cursor.execute("""
            INSERT INTO PurchaseOrderVendorBill_Header (
                NetSuiteID, TranID, TransactionNumber, PurchaseOrderID,
                VendorID, TranDate, DueDate, Status,
                Total, TaxTotal, AmountPaid, AmountDue,
                Terms, Memo, Currency, Voided,
                CreatedDate, LastModifiedDate
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        row.get('id'), row.get('tranid'), row.get('transactionnumber'),
        row.get('createdfrom'),
        row.get('entity'), row.get('trandate'), row.get('duedate'),
        row.get('status'),
        safe_decimal(row.get('total')), safe_decimal(row.get('taxtotal')),
        safe_decimal(row.get('amountpaid')),
        safe_decimal(row.get('amountremaining')),  # maps to AmountDue in DDL
        row.get('terms'),
        safe_str(row.get('memo')),
        row.get('currency'),
        safe_bool(row.get('voided')),
        row.get('createddate'), row.get('lastmodifieddate'))

    conn.commit()
    print(f"  Loaded {len(headers) - skipped} vendor bill headers ({skipped} skipped)")

    print("Loading PurchaseOrderVendorBill_Detail...")
    details = extract_all("""
        SELECT vendorBill, line, item, itemType, description,
               quantity, amount, rate, grossAmt,
               class, department, location
        FROM VendorBillItem
    """)

    skipped = 0
    for row in details:
        if not row.get('vendorbill'):
            print(f"  SKIP vendor bill detail row — missing vendorbill FK: {row}")
            skipped += 1
            continue
        cursor.execute("""
            INSERT INTO PurchaseOrderVendorBill_Detail (
                VendorBillID, Line, ItemID, ItemType, Description,
                Quantity, Amount, Rate, GrossAmt,
                Class, Department, Location
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        row.get('vendorbill'), safe_int(row.get('line')),
        row.get('item'), row.get('itemtype'),
        safe_str(row.get('description')),
        safe_decimal(row.get('quantity')), safe_decimal(row.get('amount')),
        safe_decimal(row.get('rate')), safe_decimal(row.get('grossamt')),
        row.get('class'), row.get('department'), row.get('location'))

    conn.commit()
    print(f"  Loaded {len(details) - skipped} vendor bill detail lines ({skipped} skipped)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Starting NetSuite ETL...")
    conn = get_sql_connection()

    # Dimensions first
    load_customers(conn)
    load_vendors(conn)
    load_items(conn)

    # Sales-side facts
    load_sales_orders(conn)
    load_sales_order_fulfillments(conn)
    load_sales_order_invoices(conn)

    # Purchase-side facts
    load_purchase_orders(conn)
    load_purchase_order_receipts(conn)
    load_purchase_order_vendor_bills(conn)

    conn.close()
    print("ETL complete!")
