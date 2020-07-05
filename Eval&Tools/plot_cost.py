# Figure
# Cost of calling contract functions

import numpy as np
import matplotlib.pyplot as plt
from sklearn import datasets, linear_model

x = np.linspace(1, 10, 10)
y1 = [92498,107498,122498,137498,152498,167498,182498,197498,212498,227498] # Cost: DB calling confirm()
y2 = [80717,98029,115341,132653,149965,167277,184589,201901,219213,236525] # Cost: DC calling request()
y3 = [134563,148916,163946,179651,196033,213091,230826,249236,268323,288681] # Cost: DB calling computationComplete()
y4 = [91323,99915,108507,117099,125691,134283,142875,151467,160059,168651] # Cost: DC calling completeTransaction()

y5 = []


# Create linear regression object
regr1 = linear_model.LinearRegression()
regr2 = linear_model.LinearRegression()
regr3 = linear_model.LinearRegression()
regr4 = linear_model.LinearRegression()
regr1.fit(x.reshape(-1, 1), y1)
regr2.fit(x.reshape(-1, 1), y2)
regr3.fit(x.reshape(-1, 1), y3)
regr4.fit(x.reshape(-1, 1), y4)
print('Coefficients: \n', regr1.coef_)
print('Coefficients: \n', regr2.coef_)
print('Coefficients: \n', regr3.coef_)
print('Coefficients: \n', regr4.coef_)



fig, ax = plt.subplots()

# Using set_dashes() to modify dashing of an existing line
line1 = ax.plot(x, y1, 'o-', label='DataBroker calling confirm()', color='magenta', markersize=7)
# line1.set_dashes([2, 2, 10, 2])  # 2pt line, 2pt break, 10pt line, 2pt break
line2 = ax.plot(x, y2, 'v-', label='DataConsumer calling request()', color='red', markersize=7)
line3 = ax.plot(x, y3, '^-', label='DataConsumer calling computationComplete()', color='blue', markersize=7)
line4 = ax.plot(x, y4, 's-', label='DataBroker calling completeTransaction()', color='green', markersize=7)

# Using plot(..., dashes=...) to set the dashing when creating a line
# line2, = ax.plot(x, y - 0.2, dashes=[6, 2], label='Using the dashes parameter')

# ax2 = ax.twinx()
# ax2.set_ylabel('Cost ($)')

ax.set_xlabel('N (Number of DataOwners)', fontsize = 12)
ax.set_ylabel('Cost in Gas (Dollar Equiv.)', fontsize = 12)
# ax.set_title('Cost of Calling DataBroker\'s Contract Functions', fontsize = 32)
ax.legend(fontsize=11,loc='lower right')

# plt.ylim(0,300000)
plt.xticks(x, ['1','2','3','4','5','6','7','8','9','10'], fontsize=11)
plt.yticks([0,50000,100000,150000,200000,250000,300000], ['0', '50000\n($0.00989)','100000\n($0.01979)','150000\n($0.02968)',
														'200000\n($0.03957)','250000\n($0.04946)','300000\n($0.05936)'], fontsize=11)

plt.text(6, 195000, r'$\Delta = 15000$ (\$0.00297)', color='magenta', fontsize=11, rotation=22)
plt.text(6, 235000, r'$\Delta = 17312$ (\$0.00343)', color='red', fontsize=11, rotation=25)
plt.text(6, 285000, r'$\Delta = 17081$ (\$0.00338)', color='blue', fontsize=11, rotation=27)
plt.text(6, 140000, r'$\Delta =  8592$ (\$0.00170)', color='green', fontsize=11, rotation=12)

# plt.title(r'$\alpha$')
plt.grid()
plt.show()
