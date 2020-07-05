# Figure
# Running times of computation tasks

import numpy as np
import matplotlib.pyplot as plt
# from brokenaxes import brokenaxes


# x = np.linspace(1, 8, 8)
x = np.array([1,16,32,48,64,80,96,112,128])
y1 = [0.075,0.876,1.748,2.614,3.494,4.361,5.230,6.102,6.991] # DataBroker attesting to DataOwners TCSNUM = 1 (sequential)
y2 = [0.082,0.847,1.691,2.532,3.382,4.228,5.067,5.907,6.749] # DataBroker attesting to DataOwners TCSNUM = 4
y3 = [0.072,0.843,1.671,2.502,3.328,4.160,4.984,5.811,6.646] # DataBroker attesting to DataOwners TCSNUM = 128

z1 = [0.065,0.876,1.745,2.607,3.480,4.340,5.222,6.083,6.953] # CEE attesting to DataOwners TCSNUM = 1 (sequential)
z2 = [0.081,0.846,1.687,2.540,3.378,4.216,5.055,5.893,6.723] # CEE attesting to DataOwners TCSNUM = 4


fig, ax = plt.subplots()
# ax = brokenaxes(ylims=((0, 20.0), (100.0, 140.0)), hspace=.1)

line1 = ax.plot(x, y1, '+--',  label='DataBroker, sequential (30.88MB enclave)', color='blue', markersize=6)
line2 = ax.plot(x, y2, 'o-',  label='DataBroker, 4 threads (32.51MB enclave)', color='magenta', markersize=6)
line3 = ax.plot(x, y3, 's-',  label='DataBroker, 128 threads (99.55MB enclave)', color='black', markersize=6)

line4 = ax.plot(x, z1, '+-.',  label='CEE, sequential (98.24MB enclave)', color='red', markersize=6)
line5 = ax.plot(x, z2, 'd-',  label='CEE, 4 threads (99.86MB enclave)', color='darkgreen',  markersize=6)




ax.set_xlabel('N (Number of DataOwners)', fontsize=12)
ax.set_ylabel('Attestation Time (seconds)', fontsize=12)
# ax.set_title('Runtimes of Training a 14x8x8x2 ANN Classifier', fontsize=14)
ax.legend(fontsize = 12, loc = 'upper left')

# plt.ylim(-5,170)
plt.ylim(0,8)
plt.xticks(x, ['1','16','32','48','64','80','96','112','128'], fontsize=11)
# plt.yticks([-10,0,20,40,60,80,100,120,140,160], ['-10','0','20','40','60','80','100','120','140','160'], fontsize=11)

# plt.text(80, 15, 'DataBroker \nenclave size: 2.3 MB', color='magenta', fontsize=12)
# plt.text(90, 60, 'CEE enclave size: \n118.7 MB', color='blue', fontsize=12)

plt.grid()
plt.show()