# Figure
# Running times of computation tasks

import numpy as np
import matplotlib.pyplot as plt
# from brokenaxes import brokenaxes


# x = np.linspace(1, 8, 8)
x = np.array([1,16,32,48,64,80,96,112,128,144,160])
y1 = [0.685,10.985,22.058,33.032,43.961,55.007,66.084,77.082,87.850,99.113,110.151] # DataBroker attesting to parallel DataOwners TCSNUM = 1 (sequential)
y2 = [0.674,3.366,6.728,10.147,13.515,16.896,20.277,23.582,26.979,30.460,33.799] # DataBroker attesting to parallel DataOwners TCSNUM = 4
y3 = [0.688,1.500,2.956,4.501,6.012,7.448,8.899,10.395,11.929,13.343,14.831] # DataBroker attesting to parallel DataOwners TCSNUM = 16
y4 = [0.689,1.509,2.386,3.834,4.746,6.173,6.990,8.457,9.255,10.822,11.712] # DataBroker attesting to parallel DataOwners TCSNUM = 32
y5 = [0.690,1.506,2.376,3.203,4.030,5.557,6.387,7.285,8.157,9.583,10.398] # DataBroker attesting to parallel DataOwners TCSNUM = 64
y6 = [0.697,1.517,2.396,3.287,4.143,4.972,5.838,6.612,7.467,8.972,9.881] # DataBroker attesting to parallel DataOwners TCSNUM = 128


fig, ax = plt.subplots()
# ax = brokenaxes(ylims=((0, 20.0), (100.0, 140.0)), hspace=.1)

line1 = ax.plot(x, y1, 'o-',  label='Sequential (30.88MB enclave)', color='black', markersize=6)
line2 = ax.plot(x, y2, 'x-',  label='4 threads (32.51MB enclave)', color='magenta', markersize=6)
line3 = ax.plot(x, y3, 's-',  label='16 threads (38.99MB enclave)', color='green', markersize=6)
# line4 = ax.plot(x, y4, 's-',  label='32 threads (47.64MB enclave)', color='red', markersize=6)
line5 = ax.plot(x, y5, '^-',  label='64 threads (64.95MB enclave)', color='blue', markersize=6)
# line6 = ax.plot(x, y6, 'o-',  label='128 threads (99.55MB enclave)', color='cyan', markersize=6)





ax.set_xlabel('N (Number of DataOwners)', fontsize=12)
ax.set_ylabel('Attestation Time (seconds)', fontsize=12)
# ax.set_title('Runtimes of Training a 14x8x8x2 ANN Classifier', fontsize=14)
ax.legend(fontsize = 12, loc = 'upper left')

# plt.ylim(-5,170)
# plt.ylim(0,8)
plt.xticks(x, ['1','16','32','48','64','80','96','112','128','144','160'], fontsize=11)
# plt.yticks([-10,0,20,40,60,80,100,120,140,160], ['-10','0','20','40','60','80','100','120','140','160'], fontsize=11)

# plt.text(80, 15, 'DataBroker \nenclave size: 2.3 MB', color='magenta', fontsize=12)
# plt.text(90, 60, 'CEE enclave size: \n118.7 MB', color='blue', fontsize=12)

plt.grid()
plt.show()