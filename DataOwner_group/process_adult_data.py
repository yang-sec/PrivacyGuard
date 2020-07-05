import numpy as np
import sys
import random
from datetime import datetime

# print('Number of arguments:', len(sys.argv), 'arguments.')
# print('Argument List:', str(sys.argv))

N = int(sys.argv[3])
K = 14
C = 2


file_in = open("DataFiles/Reserved_ML_Data/adult.txt", "r")
file_out = open("DataFiles/DO"+sys.argv[1]+"_"+sys.argv[2]+".txt", "w")
lines = file_in.readlines()

data = np.empty((N, K+1))

label = {'>':'+1', '<':'-1'}
workclass = {'?':0, 'Private':1, 'Self-emp-not-inc':2, 'Self-emp-inc':3, 'Federal-gov':4, 'Local-gov':5, 'State-gov':6, 'Without-pay':7, 'Never-worked':8}
education = {'?':0, 'Bachelors':1, 'Some-college':2, '11th':3, 'HS-grad':4, 'Prof-school':5, 'Assoc-acdm':6, 'Assoc-voc':7, '9th':8, '7th-8th':9, '12th':10,
			 'Masters':11, '1st-4th':12, '10th':13, 'Doctorate':14, '5th-6th':15, 'Preschool':16}
marital_status = {'?':0, 'Married-civ-spouse':1, 'Divorced':2, 'Never-married':3, 'Separated':4, 'Widowed':5, 'Married-spouse-absent':6, 'Married-AF-spouse':7}
occupation = {'?':0, 'Tech-support':1, 'Craft-repair':2, 'Other-service':3, 'Sales':4, 'Exec-managerial':5, 'Prof-specialty':6, 'Handlers-cleaners':7,
			  'Machine-op-inspct':8, 'Adm-clerical':9, 'Farming-fishing':10, 'Transport-moving':11, 'Priv-house-serv':12, 'Protective-serv':13, 'Armed-Forces':14}
relationship = {'?':0, 'Wife':1, 'Own-child':2, 'Husband':3, 'Not-in-family':4, 'Other-relative':5, 'Unmarried':6}
race = {'?':0, 'White':1, 'Asian-Pac-Islander':2, 'Amer-Indian-Eskimo':3, 'Other':4, 'Black':5}
sex = {'?':0, 'Female':1, 'Male':2}
native_country = {'?':0, 'United-States':1, 'Cambodia':2, 'England':3, 'Puerto-Rico':4, 'Canada':5, 'Germany':6, 'Outlying-US(Guam-USVI-etc)':7, 'India':8,
				  'Japan':9, 'Greece':10, 'South':11, 'China':12, 'Cuba':13, 'Iran':14, 'Honduras':15, 'Philippines':16, 'Italy':17, 'Poland':18,
				  'Jamaica':19, 'Vietnam':20, 'Mexico':21, 'Portugal':22, 'Ireland':23, 'France':24, 'Dominican-Republic':25, 'Laos':26, 'Ecuador':27,
				  'Taiwan':28, 'Haiti':29, 'Columbia':30, 'Hungary':31, 'Guatemala':32, 'Nicaragua':33, 'Scotland':34, 'Thailand':35, 'Yugoslavia':36,
				  'El-Salvador':37, 'Trinadad&Tobago':38, 'Peru':39, 'Hong':40, 'Holand-Netherlands':41}

# Randomly shuffle so that DO gets different data for every generation
random.seed(datetime.now())
rand_idx = list(range(30000))
random.shuffle(rand_idx)


# Generate data
for i in range(N):
	# print(i, rand_idx[i])
	words = lines[rand_idx[i]].split(', ')
	# print(words)

	# Label
	data[i][0] = label[words[14][0]]

	# Feature 1: age
	data[i][1] = int(words[0])

	# Feature 2: workclass
	data[i][2] = workclass[words[1]]

	# Feature 3: fnlwgt
	data[i][3] = int(words[2])

	# Feature 4: education
	data[i][4] = education[words[3]]

	# Feature 5: education-num
	data[i][5] = int(words[4])

	# Feature 6: marital-status
	data[i][6] = marital_status[words[5]]

	# Feature 7: occupation
	data[i][7] = occupation[words[6]]

	# Feature 8: relationship
	data[i][8] = relationship[words[7]]

	# Feature 9: race
	data[i][9] = race[words[8]]

	# Feature 10: sex
	data[i][10] = sex[words[9]]

	# Feature 11: capital-gain
	data[i][11] = int(words[10])

	# Feature 12: capital-loss
	data[i][12] = int(words[11])

	# Feature 13: hours-per-week
	data[i][13] = int(words[12])

	# Feature 14: native-country
	data[i][14] = native_country[words[13]]

print('N = ' + str(N) + ', K = ' + str(K) + ', C = ' + str(C))
# print(data)

# Normalize data  to -1:+1
min_row = np.min(data, 0)
max_row = np.max(data, 0)
data = 2*(data - min_row) / (max_row - min_row) - 1

# print(data)

# Convert to string
data_string = str(N) + ' ' + str(K) + ' ' + str(C) + ' '

for i in range(N):
	data_string = data_string + '\n'
	if data[i][0] == 1:
		data_string = data_string + '+1 '
	else:
		data_string = data_string + '-1 '

	for j in range(K):
		data_string = data_string + str(j+1) + ':' + str(np.round(data[i,j+1], 6)) + ' '

# print(data_string)

# Save file
file_out.write(data_string)

file_in.close()
file_out.close()