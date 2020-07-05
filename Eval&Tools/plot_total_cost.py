# Figure
# Cost of calling contract functions

import numpy as np
import matplotlib.pyplot as plt
from sklearn import datasets, linear_model


N = 10

x = np.linspace(1, N, N)

a1 = 125392 # Cost: DO calling DO contract's register() (new registry)
z2 = 80402 # Cost: DC calling DO contract's request()
z3 = 134563 # Cost: DC calling DO contract's computationComplete()
z4 = 90393 # Cost: iDA calling DO contract's completeTransaction()

b1 = 156414 # Cost: DO calling DB contract's register() (new registry)
y1 = [92498,107498,122498,137498,152498,167498,182498,197498,212498,227498] # Cost: DB calling DB contract's confirm()
y2 = [80717,98029,115341,132653,149965,167277,184589,201901,219213,236525] # Cost: DC calling DB contract's request()
y3 = [134563,148916,163946,179651,196033,213091,230826,249236,268323,288681] # Cost: DC calling DB contract's computationComplete()
y4 = [91323,99915,108507,117099,125691,134283,142875,151467,160059,168651] # Cost: DB calling DB contract's completeTransaction()

# Compute the total cost for each N
TC_DB = np.zeros(N)
TC_iDA = np.zeros(N)

for i in range(N):
	n = i + 1
	TC_DB[i]  = n * b1 + y1[i] + y2[i] + y3[i] + y4[i]
	TC_iDA[i] = n * a1 + n * z2 + n * z3 + n * z4

print(TC_DB)
print(TC_iDA)

# Create linear regression object
regr1 = linear_model.LinearRegression()
regr2 = linear_model.LinearRegression()
regr1.fit(x.reshape(-1, 1), TC_DB)
regr2.fit(x.reshape(-1, 1), TC_iDA)
print('Coefficients: \n', regr1.coef_)
print('Coefficients: \n', regr2.coef_)


fig, ax = plt.subplots()

# Using set_dashes() to modify dashing of an existing line
line1 = ax.plot(x, TC_DB, 'o-', label='Total cost of DataBroker-based system', color='magenta', markersize=7)
line2 = ax.plot(x, TC_iDA, 'v-', label='Total cost of iDataAgent-based system', color='blue', markersize=7)

ax.set_xlabel('N (Number of DataOwners)', fontsize=12)
ax.set_ylabel('Cost in Gas (Dollar Equiv.)', fontsize=12)
# ax.set_title('Total Cost Comparison', fontsize=14)
ax.legend(fontsize = 12)

plt.ylim(0,4500000)
plt.xticks(x, ['1','2','3','4','5','6','7','8','9','10'], fontsize=11)
plt.yticks([0,1000000,2000000,3000000,4000000,5000000], ['0', '1000000\n($0.19785)','2000000\n($0.39570)','3000000\n($0.59355)','4000000\n($0.79140)','5000000\n($0.98925)'],fontsize=11)

plt.text(6, 1900000, r'$\Delta = 214409$ (\$0.04242)', color='magenta', fontsize=11, rotation=16)
plt.text(6, 3400000, r'$\Delta = 430750$ (\$0.08522)', color='blue', fontsize=11, rotation=32)

plt.grid()
plt.show()