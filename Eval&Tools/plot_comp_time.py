# Figure
# Running times of computation tasks

import numpy as np
import matplotlib.pyplot as plt

x = np.linspace(1000, 10000, 10)
y1 = [68.514,137.098,204.863,273.898,341.774,408.749,476.726,543.549,611.941,680.712] # Enclave version. Hyperthreading enabled.
y2 = [23.036,46.634,69.956,94.085,114.878,138.770,160.354,182.203,204.876,224.062] # Untrusted version. Hyperthreading enabled.
y3 = [102.183,203.106,306.470,405.573,505.770,615.641,708.963,807.100,914.400,1008.540] # Enclave version. Hyperthreading disabled.
y4 = [27.477,54.664,83.988,108.266,136.446,164.205,191.825,214.827,240.129,260.814] # Untrusted version. Hyperthreading disabled.

fig, ax = plt.subplots()

# Using set_dashes() to modify dashing of an existing line
line1 = ax.plot(x, y1, 's-',  label='Inside Enclave. HTT enabled', color='magenta', markersize=7)
line2 = ax.plot(x, y2, 'o-',  label='Outside Enclave. HTT enabled', color='black', markersize=7)
line3 = ax.plot(x, y3, '^--', label='Inside Enclave. HTT disabled', color='blue', markersize=7)
line4 = ax.plot(x, y4, 'v--', label='Outside Enclave. HTT disabled', color='green', markersize=7)

# ax2 = ax.twinx()
# ax2.set_ylabel('Runtime Overhead')

ax.set_xlabel('Number of Training Data Samples', fontsize=12)
ax.set_ylabel('Runtime (seconds)', fontsize=12)
# ax.set_title('Runtimes of Training a 14x8x8x2 ANN Classifier', fontsize=14)
ax.legend(fontsize = 12)

plt.ylim(0,400)
plt.xticks(x, ['1K','2K','3K','4K','5K','6K','7K','8K','9K','10K'], fontsize=11)
plt.yticks([0,100,200,300,400,500,600,700,800,900,1000,1100], ['0','100','200','300','400','550','600','700','800','900','1000','1100'], fontsize=11)

plt.text(6000, 570, 'avg. overhead = 196.55%', color='magenta', fontsize=12, rotation=24)
plt.text(6000, 90, 'base case', color='black', fontsize=12, rotation=8)
plt.text(6000, 850, 'avg. overhead = 341.37%', color='blue', fontsize=12, rotation=32)
plt.text(6000, 310, 'avg. overhead = 17.99%', color='green', fontsize=12, rotation=9)

plt.grid()
plt.show()