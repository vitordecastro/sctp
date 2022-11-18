#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  //Header file for sleep(). man 3 sleep for details.
#include <pthread.h>
 
// A normal C function that is executed as a thread
// when its name is specified in pthread_create()
void *myThreadFun(void *vargp)
{
    sleep(1);
    printf("Printing GeeksQuiz from Thread \n");
    return NULL;
}
  
int main()
{
    // pthread_t thread_id;
    // printf("Before Thread\n");
    // pthread_create(&thread_id, NULL, myThreadFun, NULL);
    // pthread_join(thread_id, NULL);
    // printf("After Thread\n");
    // exit(0);

    int n_hosts = 10;
    pthread_t thread_id_client[n_hosts], thread_id_server[n_hosts];
    
    for(int i = 0; i < n_hosts; i++) {
        thread_id_client[i] = i;
    }

    for(int i = 0; i < n_hosts; i++) {
        printf("Address: %i\n", &thread_id_client[i]);
        printf("Value: %i\n\n", thread_id_client[i]);
    }

    printf("Address: %i\n", &thread_id_client);
}