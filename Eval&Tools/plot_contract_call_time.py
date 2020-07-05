# Figure
# Times of contract function calls

import numpy as np
import matplotlib.pyplot as plt


# x = np.linspace(1, 8, 8)
x = np.array([1,16,32,48,64,80,96,112,128,144,160])
y1 = [11.347,18.694,22.724,24.619,26.942,29.968,36.295,43.399,50.380,91.505,95.497] # DOs calling register() of their own contracts
y2 = [10.331,18.377,19.158,22.663,33.650,35.492,38.588,43.221,51.158,77.397,89.880] # DOs calling register() of the DB contract


fig, ax = plt.subplots()

line1 = ax.plot(x, y1, 's-',  label='Calling register() of DataOwners\'  contracts', color='magenta', markersize=8)
line2 = ax.plot(x, y2, 'o-',  label='Calling register() of the DataBroker contract', color='blue', markersize=8)

ax.set_xlabel('N (Number of DataOwners)', fontsize=12)
ax.set_ylabel('Average Time to Finalize (seconds)', fontsize=12)
# ax.set_title('Runtimes of Training a 14x8x8x2 ANN Classifier', fontsize=14)
ax.legend(fontsize = 12, loc = 'upper left')

plt.ylim(0,120)
# plt.ylim(0,50)
plt.xticks(x, ['1','16','32','48','64','80','96','112','128','144','160'], fontsize=11)
# plt.yticks([-10,0,20,40,60,80,100,120,140,160], ['-10','0','20','40','60','80','100','120','140','160'], fontsize=11)

# plt.text(80, 15, 'DataBroker \nenclave size: 2.3 MB', color='magenta', fontsize=12)
# plt.text(90, 60, 'CEE enclave size: \n118.7 MB', color='blue', fontsize=12)

plt.grid()
plt.show()