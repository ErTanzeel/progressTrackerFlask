import pymongo


url = 'mongodb+srv://Tanzeel:tanzeel123@cluster0.hj1okol.mongodb.net/Cluster0?retryWrites=true&w=majority'

client = pymongo.MongoClient(url)
db = client['Cluster0'] 

users = db['users']
taskcollections = db['taskcollections']
