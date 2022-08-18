import mysql.connector
from scapy.all import *
from scapy.config import conf
conf.use_pcap = True

dbini = {}
with open("labrea.ini") as ini:
  for line in ini:
    (k, v) = line.rstrip().split("=")
    dbini[k] = v

mydb = mysql.connector.connect(
  host=dbini["host"],
  user=dbini["user"],
  password=dbini["password"],
  database=dbini["database"]
  )

mycursor = mydb.cursor()

mycursor.execute("SELECT COUNT(*) FROM packets")

rows = mycursor.fetchall()

i = 0
pkt = Ether()/IP()/TCP()/Raw()
while i < rows[0][0]:
  sql = "SELECT * FROM packets LIMIT {0},10000".format(i)

  while True:
    try:
      mycursor.execute(sql)
      myresult = mycursor.fetchall()
    except mysql.connector.errors.InterfaceError as err:
      print("Error: {}".format(err))
      continue
    break
  for row in myresult:
    #pkt[timestamp] = row[0]
    pkt[Ether].dst = row[1]
    pkt[Ether].src = row[2]
    pkt[Ether].type = int(row[3])
    pkt[IP].version = int(row[4])
    pkt[IP].ihl = int(row[5])
    pkt[IP].tos = int(row[6])
    pkt[IP].len = int(row[7])
    pkt[IP].id = int(row[8])
    pkt[IP].flags = row[9]
    pkt[IP].frag = int(row[10])
    pkt[IP].ttl = int(row[11])
    pkt[IP].proto = int(row[12])
    pkt[IP].chksum = int(row[13])
    pkt[IP].src = row[14]
    pkt[IP].dst = row[15]
    ipoptionssplit = row[16].split(",")
    ipoptionsraw = []
    ipoptionslist = []
    for option in ipoptionssplit:
      ipoptionsraw.append(option.strip("[(' )]"))
    optr = 0
    if len(ipoptionsraw) > 1:
      while optr < len(ipoptionsraw):
        ipoptions = ipoptionsraw[optr]
        optr += 1
        ipoptionslist.append(ipoptions)
    pkt[IP].options = ipoptionslist
    pkt[TCP].sport = int(row[17])
    pkt[TCP].dport = int(row[18])
    pkt[TCP].seq = int(row[19])
    pkt[TCP].ack = int(row[20])
    pkt[TCP].dataofs = int(row[21])
    pkt[TCP].reserved = int(row[22])
    pkt[TCP].flags = row[23]
    pkt[TCP].window = int(row[24])
    pkt[TCP].chksum = int(row[25])
    pkt[TCP].urgptr = int(row[26])
    tcpoptionssplit = row[27].split(",")
    tcpoptionsraw = []
    tcpoptionslist = []
    for option in tcpoptionssplit:
      tcpoptionsraw.append(option.strip("[(' )]"))
    optr = 0
    if len(tcpoptionsraw) > 1:
      while optr < len(tcpoptionsraw):
        if tcpoptionsraw[optr] == "NOP":
          if tcpoptionsraw[optr + 1] == "None":
            tcpoptions = (tcpoptionsraw[optr], None)
          else:
            try:
              tcpoptions = (tcpoptionsraw[optr], int(tcpoptionsraw[optr + 1]))
            except:
              tcpoptions = (tcpoptionsraw[optr], tcpoptionsraw[optr + 1])
          optr += 2
        elif not tcpoptionsraw[optr] == "Timestamp":
          try:
            tcpoptionsrawint = int(tcpoptionsraw[optr + 1])
          except:
            tcpoptionsrawint = bytes(tcpoptionsraw[optr + 1].strip("b"), 'utf-8')
          tcpoptions = (tcpoptionsraw[optr], tcpoptionsrawint)
          optr += 2
        else:
          timestampraw = (int(tcpoptionsraw[optr + 1]), int(tcpoptionsraw[optr + 2]))
          tcpoptions = (tcpoptionsraw[optr], timestampraw)
          optr += 3
        tcpoptionslist.append(tcpoptions)
    pkt[TCP].options = tcpoptionslist
    if row[28]:
      pkt[Raw].load = bytes(row[28].strip("b'"), 'utf-8')
    wrpcap("labrea.pcap",pkt,append=True)
  i += 10000
