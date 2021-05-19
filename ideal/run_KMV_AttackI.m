%%% This script runs the inflation attack on an ideal KMV implementation and generates the plots as described in
%%%
%%% P. Reviriego, A. Sánchez-Macián, S. Liu and F. Lombardi "On the Security of the K Minimum Values (KMV)
%%% Sketch", under submission to IEEE Transactions on Dependable and Secure Computing.
%%%
%%% The plots comparing with the Apache DataSketches simulation results are also generated

%%% KMV Attack  Inflate

theo_ar = [];
theo1_ar = [];

A0_ar = [];
A1_ar = [];
A2_ar = []; 
A3_ar = []; 

C_A0_ar = [];
C_A1_ar = [];
C_A2_ar = [];
C_A3_ar = [];

C_ar = round(logspace(4,9,12));

for  C = C_ar
  KMV_AttackI;
  theo_ar = [theo_ar theo]; 
  theo1_ar = [theo1_ar theo1]; 
  A0_ar = [A0_ar A0];
  A1_ar = [A1_ar A1];
  A2_ar = [A2_ar A2]; 
  A3_ar = [A3_ar A3]; 
  C_A0_ar = [C_A0_ar C_A0];
  C_A1_ar = [C_A1_ar C_A1];
  C_A2_ar = [C_A2_ar C_A2];
  C_A3_ar = [C_A3_ar C_A3];
end

figure;
plot(C_ar,C_A0_ar,'*-');
hold on;grid on
plot(C_ar,C_A1_ar,'r+-');
plot(C_ar,C_A2_ar,'gd-');
plot(C_ar,C_A3_ar,'ms-');
xlabel('Cardinality')

figure;
semilogx(C_ar,A0_ar,'b*-');
hold on;grid on
semilogx(C_ar,theo_ar,'bo');
semilogx(C_ar,A1_ar,'r+-');
semilogx(C_ar,theo1_ar,'rd');
semilogx(C_ar,A2_ar,'g>-');
semilogx(C_ar,A3_ar,'m>-');
xlabel('Cardinality')
ylabel('Elements in the attack set')
legend('First pass','First pass theo','Second pass','Second pass theo','Third pass','Fourth pass')


%%% Generate .png
figure;
semilogx(C_ar,A0_ar,'b*-','MarkerSize',12,'LineWidth',2)
hold on;grid on
semilogx(C_ar,theo_ar,'bo','MarkerSize',12,'LineWidth',2)
semilogx(C_ar,A1_ar,'r+-','MarkerSize',12,'LineWidth',2)
semilogx(C_ar,theo1_ar,'rd','MarkerSize',12,'LineWidth',2)
xlabel('Cardinality','FontSize',14)
ylabel('Elements in the attack set','FontSize',14)
legend('Initial set I','Initial set theoretical','Final set A','Final set theoretical','Location','NorthWest','FontSize',14)

print -dpng AI1



%%% Generate .png
%%% Results on datasketches

C_S = [9694       28425       83197      237311      650962     1830497     5296687    15089133    42423632   123132774   352047781   963458693]
C_A0S = [9479       27901       84386      242735      631493     1820136     5174553    14295928    41580805   121673190   347997929   928360155]
C_A1S = [9479       27839       84149      237519      629449     1800801     5227616    14490804    41300057   122388475   341899808   932133408]



figure;
semilogx(C_ar,C_A0S./C_S,'b*-','MarkerSize',12,'LineWidth',2)
hold on;grid on
semilogx(C_ar,C_A1S./C_S,'r+-','MarkerSize',12,'LineWidth',2)
xlabel('Cardinality','FontSize',14)
ylabel('Ratio of estimated cardinalites','FontSize',14)
legend('Initial set I versus set S','Final set A versus set S','Location','SouthWest','FontSize',14)

print -dpng AIS2






A0_sim_ar = [     4174        5674        7189        8609       10081       11615       13106       14548       16012       17483       18957 20358];
A1_sim_ar = [     2286        2283        2292        2275        2264        2284        2280        2271        2271        2278        2277 2280];

%% Datasketches KMV uses a value larger than k (see https://datasketches.apache.org/api/java/snapshot/apidocs/resources/dictionary.html#nomEntries)
corr_factor = 1.0;

figure;
semilogx(C_ar,A0_sim_ar,'b*-','MarkerSize',12,'LineWidth',2)
hold on;grid on
semilogx(C_ar,corr_factor*theo_ar,'bo','MarkerSize',12,'LineWidth',2)
semilogx(C_ar,A1_sim_ar,'r+-','MarkerSize',12,'LineWidth',2)
semilogx(C_ar,corr_factor*theo1_ar,'rd','MarkerSize',12,'LineWidth',2)
xlabel('Cardinality','FontSize',14)
ylabel('Elements in the attack set','FontSize',14)
legend('Initial set I','Initial set theoretical','Final set A','Final set theoretical','Location','NorthWest','FontSize',14)

print -dpng AIS1







figure;
semilogx(C_ar,A1_ar,'r+-');
hold on;grid on
semilogx(C_ar,theo1_ar,'rd');
semilogx(C_ar,A2_ar,'g>-');
semilogx(C_ar,A3_ar,'m>-');
xlabel('Cardinality')
ylabel('Elements in the attack set')
legend('Second pass','Second pass theo','Third pass','Fourth pass')
