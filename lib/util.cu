#include "util.cu.h"
#include "log.h"
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
//#include <sys/types.h>
//#include <sys/socket.h>
#include <arpa/inet.h> // IPPROTO_TCP, IPPROTO_ICMP

// returns a timestamp in nanoseconds
// based on rdtsc on reasonably configured systems and is hence fast
uint64_t monotonic_time() {
	struct timespec timespec;
	clock_gettime(CLOCK_MONOTONIC, &timespec);
	return timespec.tv_sec * 1000 * 1000 * 1000 + timespec.tv_nsec;
}

void monitoring_loop(uint32_t** pkt_cnt, uint32_t** pkt_size)
{
	START_GRN
		printf("[Monitoring] Control is returned to CPU!\n");
	END

	uint32_t prev_pkt[2] = {0,}, cur_pkt[2] = {0,};
	double pkts[2] = {0};
	char units[] = {' ', 'K', 'M', 'G', 'T'};
	char pps[2][40] = {0};
	char bps[2][40] = {0};
	uint32_t p_size = 0;
	int i = 0, j = 0;
	int elapsed_time = 0;

	uint64_t last_stats_printed = monotonic_time();
	uint64_t time = 0;

	while(1)                                           
	{
		time = monotonic_time();
		if(time - last_stats_printed > 1000 * 1000 * 1000){
			elapsed_time++; // 1 sec +
			last_stats_printed = time;
#if 1
			ASSERTRT(cudaMemcpy(&cur_pkt[0], &(*pkt_cnt)[0], sizeof(uint32_t), cudaMemcpyDeviceToHost));
			ASSERTRT(cudaMemcpy(&cur_pkt[1], &(*pkt_cnt)[1], sizeof(uint32_t), cudaMemcpyDeviceToHost));
#else

			ASSERTRT(cudaMemcpy(&cur_pkt[0], pkt_cnt[0], sizeof(int), cudaMemcpyDeviceToHost));
			ASSERTRT(cudaMemcpy(&cur_pkt[1], pkt_cnt[1], sizeof(int), cudaMemcpyDeviceToHost));
#endif
			ASSERTRT(cudaMemcpy(&p_size, *pkt_size, sizeof(uint32_t), cudaMemcpyDeviceToHost));
			p_size += 4;

			system("clear");	
#if 0
			printf("[CKJUNG] buf #0\n");
			for(i = 0; i < 1024; i++){
				printf("%d ", data[i]);
			}
			printf("\n\n");
#endif
			for(i = 0; i < 2; i++){
				double tmp_pps;
				double tmp;
				//double batch;
				if (prev_pkt[i] != cur_pkt[i]){ // If we got a traffic flow
					//printf("prev != cur________________prev_pkt[%d]: %d, cur_pkt[%d]: %d\n", i, prev_pkt[i], i, cur_pkt[i]);
					pkts[i] = (double)(cur_pkt[i] - prev_pkt[i]);

#if 0
					if(i == 0)
						printf("RX_pkts: %d\n", (int)pkts[i]); 
					else
						printf("TX_pkts: %d\n", (int)pkts[i]); 
#endif
					tmp = tmp_pps = pkts[i];
					//batch = tmp/BATCH;
					for(j = 0; tmp >= 1000 && j < sizeof(units)/sizeof(char) -1; j++)
						tmp /= 1000;
					sprintf(pps[i],"%.3lf %c" ,tmp, units[j]);
#if 0
					p_size = PKT_SIZE;
#endif

					//tmp = pkts[i] * p_size * 8; // Bytes -> Bits
					tmp = pkts[i] * p_size * 8 + tmp_pps * 20 * 8; // Add IFG also, 20.01.15, CKJUNG
					for(j = 0; tmp >= 1000 && j < sizeof(units)/sizeof(char) -1; j++)
						tmp /= 1000;

					double percent = 10.0;
					percent = tmp/percent*100;
					sprintf(bps[i],"%.3lf %c" ,tmp, units[j]);

					if(i == 0){
						//printf("[RX] pps: %spps %sbps(%.2lf %), pkt_size: %d \n", pps[i], bps[i], percent, p_size);
						printf("[RX] pps: %spps %sbps(", pps[i], bps[i]);
						if(percent >= 99){
							START_GRN
								printf("%.2lf %%",percent);
							END
						}else{
							START_YLW
								printf("%.2lf %%",percent);
							END
						}
						printf("), pkt_size: ");
						START_RED
							printf("%d \n", p_size);
						END
					}else{
						/*
							 printf("[TX] pps: %spps %sbps(%.2lf %%), pkt_size: ", pps[i], bps[i], percent);
						 */

						printf("[TX] pps: %spps %sbps(", pps[i], bps[i]);
						if(percent >= 99){
							START_GRN
								printf("%.2lf %%",percent);
							END
						}else{
							START_YLW
								printf("%.2lf %%",percent);
							END
						}
						printf("), pkt_size: ");
						START_RED
							printf("%d \n", p_size);
						END
					}
				}else{
					if(i == 0)
						printf("[RX] pps: None\n");
					else
						printf("[TX] pps: None\n");
				}
			}
			int second = elapsed_time%60;
			int minute = elapsed_time/60;

			printf("\nElapsed:%3d m %3d s\n(ctrl + c) to stop.\n", minute, second);
#if 0
			for(i = 0; i<STATUS_SIZE; i++)
			{
				if(i % 512 ==0)
					printf("\n\n");
				if(buf_idx[i] == 1){
					START_GRN
						printf("%d ", buf_idx[i]);
					END
				}else if(buf_idx[i] == 2){
					START_RED
						printf("%d ", buf_idx[i]);
					END
				}else if(buf_idx[i] == 3){
					START_BLU
						printf("%d ", buf_idx[i]);
					END
				}else{
					printf("%d ", buf_idx[i]);
				}
			}
			printf("\n");
#endif
			prev_pkt[0] = cur_pkt[0];
			prev_pkt[1] = cur_pkt[1];
		}
		//sleep(1); 
	}                                                                  
}
