%%% This script models the deflation attack on an ideal KMV implementation as described in
%%%
%%% P. Reviriego, A. Sánchez-Macián, S. Liu and F. Lombardi "On the Security of the K Minimum Values (KMV)
%%% Sketch", under submission to IEEE Transactions on Dependable and Secure Computing.
%%%



%%% KMV Attack Deflate

% Parameters

K = 1024;
%K = 4096;


C = 10^7*2;
%C = max(10^5,100*(a+K))
%a= 512; 

% Variables

S = rand(1,C);

KMV = 1:K;
maxK = 1;
Kest = 0;

A = [];
j = 0;

for i=1:C
  j = j+1;
  if S(i) < maxK
    KMV(end) = S(i);
    KMV = sort(KMV);
    maxK = KMV(end); 
  else  % Add elements that do not increase the estimate to the attack set
    if (length(A) == 0)
      Kest = i;
    end    
    A = [A S(i)]; 
    if length(A) > 99999
      C = i;
      break;
    end  
    if (j > Kest+a)
      % Reset the KMV
      KMV = 1:K;
      maxK = 1;
      j =0;
    end    
  end
end 


S = A;

KMV = 1:K;
maxK = 1;
for i=1:length(S)
  if S(i) < maxK
    KMV(end) = S(i);
    KMV = sort(KMV);
    maxK = KMV(end); 
  end
end 

C
C_est = (K-1)/maxK
C_theo = K+a-1

L_A = length(A)/C
theo = (a - K*log((K+a-1)/K) )/(K+a-1)

