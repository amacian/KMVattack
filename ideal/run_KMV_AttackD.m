%%% This script runs the deflation attack on an ideal KMV implementation and generates the plots as described in
%%%
%%% P. Reviriego, A. Sánchez-Macián, S. Liu and F. Lombardi "On the Security of the K Minimum Values (KMV)
%%% Sketch", under submission to IEEE Transactions on Dependable and Secure Computing.
%%%
%%% The plots comparing with the Apache DataSketches simulation results are also generated


%%% KMV Attack  deflate

theo_ar = [];
A_ar = [];
C_A_ar = [];
C_theo_ar = [];

a_ar = round(linspace(100,10000,8));

%a_ar = 100

for  a = a_ar
  KMV_AttackD;
  theo_ar = [theo_ar theo]; 
  A_ar = [A_ar L_A];
  C_theo_ar = [C_theo_ar C_theo];
  C_A_ar = [C_A_ar C_est];
end


figure;
plot(a_ar,C_A_ar,'b*-','MarkerSize',12,'LineWidth',2);
hold on;grid on
plot(a_ar,C_theo_ar,'o-','MarkerSize',12,'LineWidth',2);
xlabel('t','FontSize',14)
ylabel('Cardinality','FontSize',14)
legend('Simulation','Theoretical upperbound','Location','SouthEast','FontSize',14);



print -dpng AD1



figure;
plot(a_ar,A_ar,'b*-','MarkerSize',12,'LineWidth',2);
hold on;grid on
plot(a_ar,theo_ar,'o-','MarkerSize',12,'LineWidth',2);
xlabel('t','FontSize',14)
ylabel('Elements in the attack set','FontSize',14)
legend('Fraction of elements added','Theoretical estimate','Location','SouthEast','FontSize',14);

print -dpng AD2



%%%% Data sketches simulations

t_ar = [100, 1514, 2929, 4343, 5757, 7171, 8586, 10000];
C_Asim_ar = [2284, 4519, 4708, 6006, 8353, 8914, 7299, 8177];


figure;
plot(t_ar,C_Asim_ar,'b*-','MarkerSize',12,'LineWidth',2);
hold on;grid on
plot(a_ar,C_theo_ar,'o-','MarkerSize',12,'LineWidth',2);
xlabel('t','FontSize',14)
ylabel('Cardinality','FontSize',14)
legend('Simulation','Theoretical upperbound','Location','SouthEast','FontSize',14);
print -dpng ADS1



Asim_ar = 100000./[579334, 320053, 245070, 209613, 187309, 171928, 164815, 157399];



figure;
plot(t_ar,Asim_ar,'b*-','MarkerSize',12,'LineWidth',2);
hold on;grid on
plot(a_ar,theo_ar,'o-','MarkerSize',12,'LineWidth',2);
xlabel('t','FontSize',14)
ylabel('Elements in the attack set','FontSize',14)
legend('Fraction of elements added','Theoretical estimate','Location','SouthEast','FontSize',14);

print -dpng ADS2




