import sys, requests, hashlib, json

#Enter the api key here
api_key = 'ENTER_API_KEY_HERE'

#This function hashes the given file with MD5
def hashing(file):
    buffer_size = 65536
    md5 = hashlib.md5()
    with open(file, 'rb') as hf:
        file_data = hf.read(buffer_size)
        while len(file_data) > 0:
            md5.update(file_data)
            file_data = hf.read(buffer_size)
    return md5.hexdigest()

#This function prints the results in a readable way
def printing(result):
    print("\nFile name: " + result.json()['file_info']["display_name"])
    print("\nOverall Status: " + result.json()['scan_results']['scan_all_result_a'])
    engine = result.json()['scan_results']['scan_details']
    for i in engine:
        print("\nEngine: " + i)
        if(engine[i]['threat_found'] == ""):
            print("threat_found: " + "Clean")
        else:
            print("threat_found: " + engine[i]['threat_found'])
        print("def_time: " + engine[i]['def_time'])
        print("scan_results: " + str(engine[i]['scan_result_i']))


#Asks the user for the filename
file_name = input("Enter Filename: ")
file_hash = hashing(file_name)

#The requests.get will check if the file hash exists
headers = {'apikey': api_key}
search = requests.get(('https://api.metadefender.com/v4/hash/' + file_hash), headers=headers)

#If the file hash exists it will print out the results
if(search.status_code == 200):
    print("File Hash Found")
    printing(search)
    sys.exit()

#If the file hash does not exist then it will scan the file
elif(search.status_code == 404):
    print("File Hash not found \nScanning...")

    headers = {'apikey': api_key, 'filename': file_name, 'content-type': 'application/octet-stream'}
    data = open(file_name, 'rb')
    response = requests.post('https://api.metadefender.com/v4/file', data=data, headers=headers)
    data.close()

    #This will continously check the scan to check whether the scan is finished
    data_id = response.json()['data_id']
    #print(data_id)
    percent = 0
    while(percent < 100):
        headers = {'apikey': api_key}
        results = requests.get(('https://api.metadefender.com/v4/file/' + data_id), headers=headers)
        percent = results.json()['process_info']['progress_percentage']
    printing(results)
    sys.exit()

#If any request error happens then the error message will print
else:
    print("REQUEST ERROR")
    sys.exit()
