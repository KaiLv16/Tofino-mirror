# -*- coding:utf8 -*- ,
import numpy as np

data_tmp = [i for i in range(100,500,10)]
data = np.array(data_tmp) - 28

i = 0
A = data[i:i+12]+28
print(A,np.sum(A))

B = np.array([
        [-1, 1, -1, 1, 1, 1, -1, -1, 1, 1, -1, -1],
        [1, 1, -1, 1, 1, -1, -1, 1, -1, -1, -1, 1],
        [-1, -1, 1, -1, -1, 1, 1, -1, -1, 1, 1, -1],
        [-1, -1, 1, -1, 1, -1, -1, 1, 1, -1, 1, 1]
    ])

C = np.matmul(B, A.T)

print(C)