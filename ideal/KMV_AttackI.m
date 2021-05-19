
%%% This script models the inflation attack on an ideal KMV implementation as described in
%%%
%%% P. Reviriego, A. Sánchez-Macián, S. Liu and F. Lombardi "On the Security of the K Minimum Values (KMV)
%%% Sketch", under submission to IEEE Transactions on Dependable and Secure Computing.
%%%


%%% KMV Attack Inflate

% Parameters

%C = 10^7;
K = 1024;
%K = 4096;


% Variables

S = rand(1,C);

KMV = 1:K;
maxK = 1;

A = [];

for i=1:C
  if S(i) < maxK
    KMV(end) = S(i);
    KMV = sort(KMV);
    maxK = KMV(end); 
    A = [A S(i)]; 
  end
end 

C_A0 = (K-1)/maxK
A0= length(A)

S = fliplr(A);
A = [];

KMV = 1:K;
maxK = 1;
for i=1:length(S)
  if S(i) < maxK
    KMV(end) = S(i);
    KMV = sort(KMV);
    maxK = KMV(end); 
    A = [A S(i)]; 
  end
end 

C_A1 = (K-1)/maxK
A1 = length(A)


S = A(randperm(length(A)));
A = [];

KMV = 1:K;
maxK = 1;
for i=1:length(S)
  if S(i) < maxK
    KMV(end) = S(i);
    KMV = sort(KMV);
    maxK = KMV(end); 
    A = [A S(i)]; 
  end
end 

C_A2 = (K-1)/maxK
A2 = length(A)

S = fliplr(A);
A = [];

KMV = 1:K;
maxK = 1;
for i=1:length(S)
  if S(i) < maxK
    KMV(end) = S(i);
    KMV = sort(KMV);
    maxK = KMV(end); 
    A = [A S(i)]; 
  end
end 

C_A3 = (K-1)/maxK
A3 = length(A)

theo = K+ K*log((C-1)/K)
theo1 = K+ K* (1/exp(1))/(1-1/exp(1))