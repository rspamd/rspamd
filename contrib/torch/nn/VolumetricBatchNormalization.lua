local BN, parent = torch.class('nn.VolumetricBatchNormalization', 'nn.BatchNormalization')

-- expected dimension of input
BN.nDim = 5
