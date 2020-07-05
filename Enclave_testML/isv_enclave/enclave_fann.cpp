#include "fann.h"

#include <assert.h>
#include "isv_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "string.h"
#include "isv_enclave_t.h"  /* print_string */

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <cstring>
#include <string>
// #include <string.h>
#include <cmath>

#include <math.h>
#include <stdlib.h>
#include <ctype.h>
#include <float.h>
#include <stdarg.h>
#include <limits.h>
#include "enclave_utilities.h"


FANN_EXTERNAL struct fann *FANN_API fann_create_standard(unsigned int num_layers, ...)
{
    struct fann *ann;
    va_list layer_sizes;
    int i;
    int status;
    int arg;
    unsigned int *layers = (unsigned int *) calloc(num_layers, sizeof(unsigned int));

    if(layers == NULL)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_create_standard(): FANN_E_CANT_ALLOCATE_MEM\n");
        return NULL;
    }

    va_start(layer_sizes, num_layers);
    
    status = 1;
    for(i = 0; i < (int) num_layers; i++)
    {
        arg = va_arg(layer_sizes, unsigned int);
        if(arg < 0 || arg > 1000000)
            status = 0;
        layers[i] = arg;
    }
    va_end(layer_sizes);

    if(!status)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_create_standard(): FANN_E_CANT_ALLOCATE_MEM\n");
        free(layers);
        return NULL;
    }

    ann = fann_create_standard_array(num_layers, layers);

    free(layers);

    return ann;
}

FANN_EXTERNAL struct fann *FANN_API fann_create_standard_array(unsigned int num_layers, 
                                                               const unsigned int *layers)
{
    return fann_create_sparse_array(1, num_layers, layers); 
}

FANN_EXTERNAL struct fann *FANN_API fann_create_sparse(float connection_rate, 
                                                       unsigned int num_layers, ...)
{
    struct fann *ann;
    va_list layer_sizes;
    int i;
    int status;
    int arg;
    unsigned int *layers = (unsigned int *) calloc(num_layers, sizeof(unsigned int));

    if(layers == NULL)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_create_sparse(): FANN_E_CANT_ALLOCATE_MEM\n");
        return NULL;
    }

    va_start(layer_sizes, num_layers);
    status = 1;
    for(i = 0; i < (int) num_layers; i++)
    {
        arg = va_arg(layer_sizes, unsigned int);
        if(arg < 0 || arg > 1000000)
            status = 0;
        layers[i] = arg;
    }
    va_end(layer_sizes);

    if(!status)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_create_sparse(): FANN_E_CANT_ALLOCATE_MEM\n");
        free(layers);
        return NULL;
    }

    ann = fann_create_sparse_array(connection_rate, num_layers, layers);
    free(layers);

    return ann;
}

FANN_EXTERNAL struct fann *FANN_API fann_create_sparse_array(float connection_rate,
                                                             unsigned int num_layers,
                                                             const unsigned int *layers)
{
    struct fann_layer *layer_it, *last_layer, *prev_layer;
    struct fann *ann;
    struct fann_neuron *neuron_it, *last_neuron, *random_neuron, *bias_neuron;
#ifdef DEBUG
    unsigned int prev_layer_size;
#endif
    unsigned int num_neurons_in, num_neurons_out, i, j;
    unsigned int min_connections, max_connections, num_connections;
    unsigned int connections_per_neuron, allocated_connections;
    unsigned int random_number, found_connection, tmp_con;

#ifdef FIXEDFANN
    unsigned int multiplier;
#endif
    if(connection_rate > 1)
    {
        connection_rate = 1;
    }

    // fann_seed_rand();

    /* allocate the general structure */
    ann = fann_allocate_structure(num_layers);
    if(ann == NULL)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_create_sparse_array(): FANN_E_CANT_ALLOCATE_MEM\n");
        return NULL;
    }

    ann->connection_rate = connection_rate;
#ifdef FIXEDFANN
    multiplier = ann->multiplier;
    fann_update_stepwise(ann);
#endif

    /* determine how many neurons there should be in each layer */
    i = 0;
    for(layer_it = ann->first_layer; layer_it != ann->last_layer; layer_it++)
    {
        /* we do not allocate room here, but we make sure that
         * last_neuron - first_neuron is the number of neurons */
        layer_it->first_neuron = NULL;
        layer_it->last_neuron = layer_it->first_neuron + layers[i++] + 1;   /* +1 for bias */
        ann->total_neurons += (unsigned int)(layer_it->last_neuron - layer_it->first_neuron);
    }

    ann->num_output = (unsigned int)((ann->last_layer - 1)->last_neuron - (ann->last_layer - 1)->first_neuron - 1);
    ann->num_input = (unsigned int)(ann->first_layer->last_neuron - ann->first_layer->first_neuron - 1);

    /* allocate room for the actual neurons */
    fann_allocate_neurons(ann);
    if(ann->errno_f == FANN_E_CANT_ALLOCATE_MEM)
    {
        fann_destroy(ann);
        return NULL;
    }

#ifdef DEBUG
    printf("creating network with connection rate %f\n", connection_rate);
    printf("input\n");
    printf("  layer       : %d neurons, 1 bias\n",
           (int)(ann->first_layer->last_neuron - ann->first_layer->first_neuron - 1));
#endif

    num_neurons_in = ann->num_input;
    for(layer_it = ann->first_layer + 1; layer_it != ann->last_layer; layer_it++)
    {
        num_neurons_out = (unsigned int)(layer_it->last_neuron - layer_it->first_neuron - 1);
        /*�if all neurons in each layer should be connected to at least one neuron
         * in the previous layer, and one neuron in the next layer.
         * and the bias node should be connected to the all neurons in the next layer.
         * Then this is the minimum amount of neurons */
        min_connections = fann_max(num_neurons_in, num_neurons_out); /* not calculating bias */
        max_connections = num_neurons_in * num_neurons_out;      /* not calculating bias */
        num_connections = fann_max(min_connections,
                                   (unsigned int) (0.5 + (connection_rate * max_connections))) +
                                   num_neurons_out;

        connections_per_neuron = num_connections / num_neurons_out;
        allocated_connections = 0;
        /* Now split out the connections on the different neurons */
        for(i = 0; i != num_neurons_out; i++)
        {
            layer_it->first_neuron[i].first_con = ann->total_connections + allocated_connections;
            allocated_connections += connections_per_neuron;
            layer_it->first_neuron[i].last_con = ann->total_connections + allocated_connections;

            layer_it->first_neuron[i].activation_function = FANN_SIGMOID_STEPWISE;
#ifdef FIXEDFANN
            layer_it->first_neuron[i].activation_steepness = ann->multiplier / 2;
#else
            layer_it->first_neuron[i].activation_steepness = 0.5;
#endif

            if(allocated_connections < (num_connections * (i + 1)) / num_neurons_out)
            {
                layer_it->first_neuron[i].last_con++;
                allocated_connections++;
            }
        }

        /* bias neuron also gets stuff */
        layer_it->first_neuron[i].first_con = ann->total_connections + allocated_connections;
        layer_it->first_neuron[i].last_con = ann->total_connections + allocated_connections;

        ann->total_connections += num_connections;

        /* used in the next run of the loop */
        num_neurons_in = num_neurons_out;
    }

    fann_allocate_connections(ann);
    if(ann->errno_f == FANN_E_CANT_ALLOCATE_MEM)
    {
        fann_destroy(ann);
        return NULL;
    }

    if(connection_rate >= 1)
    {
#ifdef DEBUG
        prev_layer_size = ann->num_input + 1;
#endif
        prev_layer = ann->first_layer;
        last_layer = ann->last_layer;
        for(layer_it = ann->first_layer + 1; layer_it != last_layer; layer_it++)
        {
            last_neuron = layer_it->last_neuron - 1;
            for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
            {
                tmp_con = neuron_it->last_con - 1;
                for(i = neuron_it->first_con; i != tmp_con; i++)
                {
                    ann->weights[i] = (fann_type) fann_random_weight();
                    /* these connections are still initialized for fully connected networks, to allow
                     * operations to work, that are not optimized for fully connected networks.
                     */
                    ann->connections[i] = prev_layer->first_neuron + (i - neuron_it->first_con);
                }

                /* bias weight */
                ann->weights[tmp_con] = (fann_type) fann_random_bias_weight();
                ann->connections[tmp_con] = prev_layer->first_neuron + (tmp_con - neuron_it->first_con);
            }
#ifdef DEBUG
            prev_layer_size = layer_it->last_neuron - layer_it->first_neuron;
#endif
            prev_layer = layer_it;
#ifdef DEBUG
            printf("  layer       : %d neurons, 1 bias\n", prev_layer_size - 1);
#endif
        }
    }
    else
    {
        /* make connections for a network, that are not fully connected */

        /* generally, what we do is first to connect all the input
         * neurons to a output neuron, respecting the number of
         * available input neurons for each output neuron. Then
         * we go through all the output neurons, and connect the
         * rest of the connections to input neurons, that they are
         * not allready connected to.
         */

        /* All the connections are cleared by calloc, because we want to
         * be able to see which connections are allready connected */

        for(layer_it = ann->first_layer + 1; layer_it != ann->last_layer; layer_it++)
        {

            num_neurons_out = (unsigned int)(layer_it->last_neuron - layer_it->first_neuron - 1);
            num_neurons_in = (unsigned int)((layer_it - 1)->last_neuron - (layer_it - 1)->first_neuron - 1);

            /* first connect the bias neuron */
            bias_neuron = (layer_it - 1)->last_neuron - 1;
            last_neuron = layer_it->last_neuron - 1;
            for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
            {

                ann->connections[neuron_it->first_con] = bias_neuron;
                ann->weights[neuron_it->first_con] = (fann_type) fann_random_bias_weight();
            }

            /* then connect all neurons in the input layer */
            last_neuron = (layer_it - 1)->last_neuron - 1;
            for(neuron_it = (layer_it - 1)->first_neuron; neuron_it != last_neuron; neuron_it++)
            {

                /* random neuron in the output layer that has space
                 * for more connections */
                do
                {
                    random_number = (int) (0.5 + fann_rand(0, num_neurons_out - 1));
                    random_neuron = layer_it->first_neuron + random_number;
                    /* checks the last space in the connections array for room */
                }
                while(ann->connections[random_neuron->last_con - 1]);

                /* find an empty space in the connection array and connect */
                for(i = random_neuron->first_con; i < random_neuron->last_con; i++)
                {
                    if(ann->connections[i] == NULL)
                    {
                        ann->connections[i] = neuron_it;
                        ann->weights[i] = (fann_type) fann_random_weight();
                        break;
                    }
                }
            }

            /* then connect the rest of the unconnected neurons */
            last_neuron = layer_it->last_neuron - 1;
            for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
            {
                /* find empty space in the connection array and connect */
                for(i = neuron_it->first_con; i < neuron_it->last_con; i++)
                {
                    /* continue if allready connected */
                    if(ann->connections[i] != NULL)
                        continue;

                    do
                    {
                        found_connection = 0;
                        random_number = (int) (0.5 + fann_rand(0, num_neurons_in - 1));
                        random_neuron = (layer_it - 1)->first_neuron + random_number;

                        /* check to see if this connection is allready there */
                        for(j = neuron_it->first_con; j < i; j++)
                        {
                            if(random_neuron == ann->connections[j])
                            {
                                found_connection = 1;
                                break;
                            }
                        }

                    }
                    while(found_connection);

                    /* we have found a neuron that is not allready
                     * connected to us, connect it */
                    ann->connections[i] = random_neuron;
                    ann->weights[i] = (fann_type) fann_random_weight();
                }
            }

#ifdef DEBUG
            printf("  layer       : %d neurons, 1 bias\n", num_neurons_out);
#endif
        }

        /* TODO it would be nice to have the randomly created
         * connections sorted for smoother memory access.
         */
    }

#ifdef DEBUG
    printf("output\n");
#endif

    return ann;
}


FANN_EXTERNAL struct fann *FANN_API fann_create_shortcut(unsigned int num_layers, ...)
{
    struct fann *ann;
    int i;
    int status;
    int arg;
    va_list layer_sizes;
    unsigned int *layers = (unsigned int *) calloc(num_layers, sizeof(unsigned int));

    if(layers == NULL)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_create_shortcut(): FANN_E_CANT_ALLOCATE_MEM\n");
        return NULL;
    }

    va_start(layer_sizes, num_layers);
    status = 1;
    for(i = 0; i < (int) num_layers; i++)
    {
        arg = va_arg(layer_sizes, unsigned int);
        if(arg < 0 || arg > 1000000)
            status = 0;
        layers[i] = arg;
    }
    va_end(layer_sizes);

    if(!status)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_create_shortcut(): FANN_E_CANT_ALLOCATE_MEM\n");
        free(layers);
        return NULL;
    }

    ann = fann_create_shortcut_array(num_layers, layers);

    free(layers);

    return ann;
}

FANN_EXTERNAL struct fann *FANN_API fann_create_shortcut_array(unsigned int num_layers,
                                                               const unsigned int *layers)
{
    struct fann_layer *layer_it, *layer_it2, *last_layer;
    struct fann *ann;
    struct fann_neuron *neuron_it, *neuron_it2 = 0;
    unsigned int i;
    unsigned int num_neurons_in, num_neurons_out;

#ifdef FIXEDFANN
    unsigned int multiplier;
#endif
    // fann_seed_rand();

    /* allocate the general structure */
    ann = fann_allocate_structure(num_layers);
    if(ann == NULL)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_allocate_structure(): FANN_E_CANT_ALLOCATE_MEM\n");
        return NULL;
    }

    ann->connection_rate = 1;
    ann->network_type = FANN_NETTYPE_SHORTCUT;
#ifdef FIXEDFANN
    multiplier = ann->multiplier;
    fann_update_stepwise(ann);
#endif

    /* determine how many neurons there should be in each layer */
    i = 0;
    for(layer_it = ann->first_layer; layer_it != ann->last_layer; layer_it++)
    {
        /* we do not allocate room here, but we make sure that
         * last_neuron - first_neuron is the number of neurons */
        layer_it->first_neuron = NULL;
        layer_it->last_neuron = layer_it->first_neuron + layers[i++];
        if(layer_it == ann->first_layer)
        {
            /* there is a bias neuron in the first layer */
            layer_it->last_neuron++;
        }

        ann->total_neurons += (unsigned int)(layer_it->last_neuron - layer_it->first_neuron);
    }

    ann->num_output = (unsigned int)((ann->last_layer - 1)->last_neuron - (ann->last_layer - 1)->first_neuron);
    ann->num_input = (unsigned int)(ann->first_layer->last_neuron - ann->first_layer->first_neuron - 1);

    /* allocate room for the actual neurons */
    fann_allocate_neurons(ann);
    if(ann->errno_f == FANN_E_CANT_ALLOCATE_MEM)
    {
        fann_destroy(ann);
        return NULL;
    }

#ifdef DEBUG
    printf("creating fully shortcut connected network.\n");
    printf("input\n");
    printf("  layer       : %d neurons, 1 bias\n",
           (int)(ann->first_layer->last_neuron - ann->first_layer->first_neuron - 1));
#endif

    num_neurons_in = ann->num_input;
    last_layer = ann->last_layer;
    for(layer_it = ann->first_layer + 1; layer_it != last_layer; layer_it++)
    {
        num_neurons_out = (unsigned int)(layer_it->last_neuron - layer_it->first_neuron);

        /* Now split out the connections on the different neurons */
        for(i = 0; i != num_neurons_out; i++)
        {
            layer_it->first_neuron[i].first_con = ann->total_connections;
            ann->total_connections += num_neurons_in + 1;
            layer_it->first_neuron[i].last_con = ann->total_connections;

            layer_it->first_neuron[i].activation_function = FANN_SIGMOID_STEPWISE;
#ifdef FIXEDFANN
            layer_it->first_neuron[i].activation_steepness = ann->multiplier / 2;
#else
            layer_it->first_neuron[i].activation_steepness = 0.5;
#endif
        }

#ifdef DEBUG
        printf("  layer       : %d neurons, 0 bias\n", num_neurons_out);
#endif
        /* used in the next run of the loop */
        num_neurons_in += num_neurons_out;
    }

    fann_allocate_connections(ann);
    if(ann->errno_f == FANN_E_CANT_ALLOCATE_MEM)
    {
        fann_destroy(ann);
        return NULL;
    }

    /* Connections are created from all neurons to all neurons in later layers
     */
    num_neurons_in = ann->num_input + 1;
    for(layer_it = ann->first_layer + 1; layer_it != last_layer; layer_it++)
    {
        for(neuron_it = layer_it->first_neuron; neuron_it != layer_it->last_neuron; neuron_it++)
        {

            i = neuron_it->first_con;
            for(layer_it2 = ann->first_layer; layer_it2 != layer_it; layer_it2++)
            {
                for(neuron_it2 = layer_it2->first_neuron; neuron_it2 != layer_it2->last_neuron;
                    neuron_it2++)
                {

                    ann->weights[i] = (fann_type) fann_random_weight();
                    ann->connections[i] = neuron_it2;
                    i++;
                }
            }
        }
        num_neurons_in += (unsigned int)(layer_it->last_neuron - layer_it->first_neuron);
    }

#ifdef DEBUG
    printf("output\n");
#endif

    return ann;
}

FANN_EXTERNAL fann_type *FANN_API fann_run(struct fann * ann, fann_type * input)
{
    struct fann_neuron *neuron_it, *last_neuron, *neurons, **neuron_pointers;
    unsigned int i, num_connections, num_input, num_output;
    fann_type neuron_sum, *output;
    fann_type *weights;
    struct fann_layer *layer_it, *last_layer;
    unsigned int activation_function;
    fann_type steepness;

    /* store some variabels local for fast access */
    struct fann_neuron *first_neuron = ann->first_layer->first_neuron;

#ifdef FIXEDFANN
    int multiplier = ann->multiplier;
    unsigned int decimal_point = ann->decimal_point;

    /* values used for the stepwise linear sigmoid function */
    fann_type r1 = 0, r2 = 0, r3 = 0, r4 = 0, r5 = 0, r6 = 0;
    fann_type v1 = 0, v2 = 0, v3 = 0, v4 = 0, v5 = 0, v6 = 0;

    fann_type last_steepness = 0;
    unsigned int last_activation_function = 0;
#else
    fann_type max_sum = 0;  
#endif

    /* first set the input */
    num_input = ann->num_input;
    for(i = 0; i != num_input; i++)
    {
#ifdef FIXEDFANN
        if(fann_abs(input[i]) > multiplier)
        {
            printf
                ("Warning input number %d is out of range -%d - %d with value %d, integer overflow may occur.\n",
                 i, multiplier, multiplier, input[i]);
        }
#endif
        first_neuron[i].value = input[i];
    }
    /* Set the bias neuron in the input layer */
#ifdef FIXEDFANN
    (ann->first_layer->last_neuron - 1)->value = multiplier;
#else
    (ann->first_layer->last_neuron - 1)->value = 1;
#endif

    last_layer = ann->last_layer;
    for(layer_it = ann->first_layer + 1; layer_it != last_layer; layer_it++)
    {
        last_neuron = layer_it->last_neuron;
        for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
        {
            if(neuron_it->first_con == neuron_it->last_con)
            {
                /* bias neurons */
#ifdef FIXEDFANN
                neuron_it->value = multiplier;
#else
                neuron_it->value = 1;
#endif
                continue;
            }

            activation_function = neuron_it->activation_function;
            steepness = neuron_it->activation_steepness;

            neuron_sum = 0;
            num_connections = neuron_it->last_con - neuron_it->first_con;
            weights = ann->weights + neuron_it->first_con;

            if(ann->connection_rate >= 1)
            {
                if(ann->network_type == FANN_NETTYPE_SHORTCUT)
                {
                    neurons = ann->first_layer->first_neuron;
                }
                else
                {
                    neurons = (layer_it - 1)->first_neuron;
                }


                /* unrolled loop start */
                i = num_connections & 3;    /* same as modulo 4 */
                switch (i)
                {
                    case 3:
                        neuron_sum += fann_mult(weights[2], neurons[2].value);
                    case 2:
                        neuron_sum += fann_mult(weights[1], neurons[1].value);
                    case 1:
                        neuron_sum += fann_mult(weights[0], neurons[0].value);
                    case 0:
                        break;
                }

                for(; i != num_connections; i += 4)
                {
                    neuron_sum +=
                        fann_mult(weights[i], neurons[i].value) +
                        fann_mult(weights[i + 1], neurons[i + 1].value) +
                        fann_mult(weights[i + 2], neurons[i + 2].value) +
                        fann_mult(weights[i + 3], neurons[i + 3].value);
                }
                /* unrolled loop end */

                /*
                 * for(i = 0;i != num_connections; i++){
                 * printf("%f += %f*%f, ", neuron_sum, weights[i], neurons[i].value);
                 * neuron_sum += fann_mult(weights[i], neurons[i].value);
                 * }
                 */
            }
            else
            {
                neuron_pointers = ann->connections + neuron_it->first_con;

                i = num_connections & 3;    /* same as modulo 4 */
                switch (i)
                {
                    case 3:
                        neuron_sum += fann_mult(weights[2], neuron_pointers[2]->value);
                    case 2:
                        neuron_sum += fann_mult(weights[1], neuron_pointers[1]->value);
                    case 1:
                        neuron_sum += fann_mult(weights[0], neuron_pointers[0]->value);
                    case 0:
                        break;
                }

                for(; i != num_connections; i += 4)
                {
                    neuron_sum +=
                        fann_mult(weights[i], neuron_pointers[i]->value) +
                        fann_mult(weights[i + 1], neuron_pointers[i + 1]->value) +
                        fann_mult(weights[i + 2], neuron_pointers[i + 2]->value) +
                        fann_mult(weights[i + 3], neuron_pointers[i + 3]->value);
                }
            }

#ifdef FIXEDFANN
            neuron_it->sum = fann_mult(steepness, neuron_sum);

            if(activation_function != last_activation_function || steepness != last_steepness)
            {
                switch (activation_function)
                {
                    case FANN_SIGMOID:
                    case FANN_SIGMOID_STEPWISE:
                        r1 = ann->sigmoid_results[0];
                        r2 = ann->sigmoid_results[1];
                        r3 = ann->sigmoid_results[2];
                        r4 = ann->sigmoid_results[3];
                        r5 = ann->sigmoid_results[4];
                        r6 = ann->sigmoid_results[5];
                        v1 = ann->sigmoid_values[0] / steepness;
                        v2 = ann->sigmoid_values[1] / steepness;
                        v3 = ann->sigmoid_values[2] / steepness;
                        v4 = ann->sigmoid_values[3] / steepness;
                        v5 = ann->sigmoid_values[4] / steepness;
                        v6 = ann->sigmoid_values[5] / steepness;
                        break;
                    case FANN_SIGMOID_SYMMETRIC:
                    case FANN_SIGMOID_SYMMETRIC_STEPWISE:
                        r1 = ann->sigmoid_symmetric_results[0];
                        r2 = ann->sigmoid_symmetric_results[1];
                        r3 = ann->sigmoid_symmetric_results[2];
                        r4 = ann->sigmoid_symmetric_results[3];
                        r5 = ann->sigmoid_symmetric_results[4];
                        r6 = ann->sigmoid_symmetric_results[5];
                        v1 = ann->sigmoid_symmetric_values[0] / steepness;
                        v2 = ann->sigmoid_symmetric_values[1] / steepness;
                        v3 = ann->sigmoid_symmetric_values[2] / steepness;
                        v4 = ann->sigmoid_symmetric_values[3] / steepness;
                        v5 = ann->sigmoid_symmetric_values[4] / steepness;
                        v6 = ann->sigmoid_symmetric_values[5] / steepness;
                        break;
                    case FANN_THRESHOLD:
                        break;
                }
            }

            switch (activation_function)
            {
                case FANN_SIGMOID:
                case FANN_SIGMOID_STEPWISE:
                    neuron_it->value =
                        (fann_type) fann_stepwise(v1, v2, v3, v4, v5, v6, r1, r2, r3, r4, r5, r6, 0,
                                                  multiplier, neuron_sum);
                    break;
                case FANN_SIGMOID_SYMMETRIC:
                case FANN_SIGMOID_SYMMETRIC_STEPWISE:
                    neuron_it->value =
                        (fann_type) fann_stepwise(v1, v2, v3, v4, v5, v6, r1, r2, r3, r4, r5, r6,
                                                  -multiplier, multiplier, neuron_sum);
                    break;
                case FANN_THRESHOLD:
                    neuron_it->value = (fann_type) ((neuron_sum < 0) ? 0 : multiplier);
                    break;
                case FANN_THRESHOLD_SYMMETRIC:
                    neuron_it->value = (fann_type) ((neuron_sum < 0) ? -multiplier : multiplier);
                    break;
                case FANN_LINEAR:
                    neuron_it->value = neuron_sum;
                    break;
                case FANN_LINEAR_PIECE:
                    neuron_it->value = (fann_type)((neuron_sum < 0) ? 0 : (neuron_sum > multiplier) ? multiplier : neuron_sum);
                    break;
                case FANN_LINEAR_PIECE_SYMMETRIC:
                    neuron_it->value = (fann_type)((neuron_sum < -multiplier) ? -multiplier : (neuron_sum > multiplier) ? multiplier : neuron_sum);
                    break;
                case FANN_ELLIOT:
                case FANN_ELLIOT_SYMMETRIC:
                case FANN_GAUSSIAN:
                case FANN_GAUSSIAN_SYMMETRIC:
                case FANN_GAUSSIAN_STEPWISE:
                case FANN_SIN_SYMMETRIC:
                case FANN_COS_SYMMETRIC:
                    fann_error((struct fann_error *) ann, FANN_E_CANT_USE_ACTIVATION);
                    break;
            }
            last_steepness = steepness;
            last_activation_function = activation_function;
#else
            neuron_sum = fann_mult(steepness, neuron_sum);
            
            max_sum = 150/steepness;
            if(neuron_sum > max_sum)
                neuron_sum = max_sum;
            else if(neuron_sum < -max_sum)
                neuron_sum = -max_sum;
            
            neuron_it->sum = neuron_sum;

            fann_activation_switch(activation_function, neuron_sum, neuron_it->value);
#endif
        }
    }

    /* set the output */
    output = ann->output;
    num_output = ann->num_output;
    neurons = (ann->last_layer - 1)->first_neuron;
    for(i = 0; i != num_output; i++)
    {
        output[i] = neurons[i].value;
    }
    return ann->output;
}

FANN_EXTERNAL void FANN_API fann_destroy(struct fann *ann)
{
    if(ann == NULL)
        return;
    fann_safe_free(ann->weights);
    fann_safe_free(ann->connections);
    fann_safe_free(ann->first_layer->first_neuron);
    fann_safe_free(ann->first_layer);
    fann_safe_free(ann->output);
    fann_safe_free(ann->train_errors);
    fann_safe_free(ann->train_slopes);
    fann_safe_free(ann->prev_train_slopes);
    fann_safe_free(ann->prev_steps);
    fann_safe_free(ann->prev_weights_deltas);
    fann_safe_free(ann->errstr);
    fann_safe_free(ann->cascade_activation_functions);
    fann_safe_free(ann->cascade_activation_steepnesses);
    fann_safe_free(ann->cascade_candidate_scores);
    
#ifndef FIXEDFANN
    fann_safe_free( ann->scale_mean_in );
    fann_safe_free( ann->scale_deviation_in );
    fann_safe_free( ann->scale_new_min_in );
    fann_safe_free( ann->scale_factor_in );

    fann_safe_free( ann->scale_mean_out );
    fann_safe_free( ann->scale_deviation_out );
    fann_safe_free( ann->scale_new_min_out );
    fann_safe_free( ann->scale_factor_out );
#endif
    
    fann_safe_free(ann);
}

FANN_EXTERNAL void FANN_API fann_randomize_weights(struct fann *ann, fann_type min_weight,
                                                   fann_type max_weight)
{
    fann_type *last_weight;
    fann_type *weights = ann->weights;

    last_weight = weights + ann->total_connections;
    for(; weights != last_weight; weights++)
    {
        *weights = (fann_type) (fann_rand(min_weight, max_weight));
    }

#ifndef FIXEDFANN
    if(ann->prev_train_slopes != NULL)
    {
        fann_clear_train_arrays(ann);
    }
#endif
}

/* deep copy of the fann structure */
FANN_EXTERNAL struct fann* FANN_API fann_copy(struct fann* orig)
{
    struct fann* copy;
    unsigned int num_layers = (unsigned int)(orig->last_layer - orig->first_layer);
    struct fann_layer *orig_layer_it, *copy_layer_it;
    unsigned int layer_size;
    struct fann_neuron *last_neuron,*orig_neuron_it,*copy_neuron_it;
    unsigned int i;
    struct fann_neuron *orig_first_neuron,*copy_first_neuron;
    unsigned int input_neuron;

    copy = fann_allocate_structure(num_layers);
    if (copy==NULL) {
        // fann_error((struct fann_error*)orig, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_copy(): FANN_E_CANT_ALLOCATE_MEM\n");
        return NULL;
    }
    copy->errno_f = orig->errno_f;
    if (orig->errstr)
    {
        copy->errstr = (char *) malloc(FANN_ERRSTR_MAX);
        if (copy->errstr == NULL)
        {
            fann_destroy(copy);
            return NULL;
        }
        // strcpy(copy->errstr,orig->errstr);
        strncpy(copy->errstr, orig->errstr, sizeof(copy->errstr));
    }
    // copy->error_log = orig->error_log;

    copy->learning_rate = orig->learning_rate;
    copy->learning_momentum = orig->learning_momentum;
    copy->connection_rate = orig->connection_rate;
    copy->network_type = orig->network_type;
    copy->num_MSE = orig->num_MSE;
    copy->MSE_value = orig->MSE_value;
    copy->num_bit_fail = orig->num_bit_fail;
    copy->bit_fail_limit = orig->bit_fail_limit;
    copy->train_error_function = orig->train_error_function;
    copy->train_stop_function = orig->train_stop_function;
    copy->training_algorithm = orig->training_algorithm;
    copy->callback = orig->callback;
    copy->user_data = orig->user_data;
#ifndef FIXEDFANN
    copy->cascade_output_change_fraction = orig->cascade_output_change_fraction;
    copy->cascade_output_stagnation_epochs = orig->cascade_output_stagnation_epochs;
    copy->cascade_candidate_change_fraction = orig->cascade_candidate_change_fraction;
    copy->cascade_candidate_stagnation_epochs = orig->cascade_candidate_stagnation_epochs;
    copy->cascade_best_candidate = orig->cascade_best_candidate;
    copy->cascade_candidate_limit = orig->cascade_candidate_limit;
    copy->cascade_weight_multiplier = orig->cascade_weight_multiplier;
    copy->cascade_max_out_epochs = orig->cascade_max_out_epochs;
    copy->cascade_max_cand_epochs = orig->cascade_max_cand_epochs;

   /* copy cascade activation functions */
    copy->cascade_activation_functions_count = orig->cascade_activation_functions_count;
    copy->cascade_activation_functions = (enum fann_activationfunc_enum *)realloc(copy->cascade_activation_functions,
        copy->cascade_activation_functions_count * sizeof(enum fann_activationfunc_enum));
    if(copy->cascade_activation_functions == NULL)
    {
        // fann_error((struct fann_error*)orig, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_copy(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy(copy);
        return NULL;
    }
    memcpy(copy->cascade_activation_functions,orig->cascade_activation_functions,
            copy->cascade_activation_functions_count * sizeof(enum fann_activationfunc_enum));

    /* copy cascade activation steepnesses */
    copy->cascade_activation_steepnesses_count = orig->cascade_activation_steepnesses_count;
    copy->cascade_activation_steepnesses = (fann_type *)realloc(copy->cascade_activation_steepnesses, copy->cascade_activation_steepnesses_count * sizeof(fann_type));
    if(copy->cascade_activation_steepnesses == NULL)
    {
        // fann_error((struct fann_error*)orig, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_copy(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy(copy);
        return NULL;
    }
    memcpy(copy->cascade_activation_steepnesses,orig->cascade_activation_steepnesses,copy->cascade_activation_steepnesses_count * sizeof(fann_type));

    copy->cascade_num_candidate_groups = orig->cascade_num_candidate_groups;

    /* copy candidate scores, if used */
    if (orig->cascade_candidate_scores == NULL)
    {
        copy->cascade_candidate_scores = NULL;
    }
    else
    {
        copy->cascade_candidate_scores =
            (fann_type *) malloc(fann_get_cascade_num_candidates(copy) * sizeof(fann_type));
        if(copy->cascade_candidate_scores == NULL)
        {
            // fann_error((struct fann_error *) orig, FANN_E_CANT_ALLOCATE_MEM);
            printf("Error: fann_copy(): FANN_E_CANT_ALLOCATE_MEM\n");
            fann_destroy(copy);
            return NULL;
        }
        memcpy(copy->cascade_candidate_scores,orig->cascade_candidate_scores,fann_get_cascade_num_candidates(copy) * sizeof(fann_type));
    }
#endif /* FIXEDFANN */

    copy->quickprop_decay = orig->quickprop_decay;
    copy->quickprop_mu = orig->quickprop_mu;
    copy->rprop_increase_factor = orig->rprop_increase_factor;
    copy->rprop_decrease_factor = orig->rprop_decrease_factor;
    copy->rprop_delta_min = orig->rprop_delta_min;
    copy->rprop_delta_max = orig->rprop_delta_max;
    copy->rprop_delta_zero = orig->rprop_delta_zero;

    /* user_data is not deep copied.  user should use fann_copy_with_user_data() for that */
    copy->user_data = orig->user_data;

#ifdef FIXEDFANN
    copy->decimal_point = orig->decimal_point;
    copy->multiplier = orig->multiplier;
    memcpy(copy->sigmoid_results,orig->sigmoid_results,6*sizeof(fann_type));
    memcpy(copy->sigmoid_values,orig->sigmoid_values,6*sizeof(fann_type));
    memcpy(copy->sigmoid_symmetric_results,orig->sigmoid_symmetric_results,6*sizeof(fann_type));
    memcpy(copy->sigmoid_symmetric_values,orig->sigmoid_symmetric_values,6*sizeof(fann_type));
#endif


    /* copy layer sizes, prepare for fann_allocate_neurons */
    for (orig_layer_it = orig->first_layer, copy_layer_it = copy->first_layer;
            orig_layer_it != orig->last_layer; orig_layer_it++, copy_layer_it++)
    {
        layer_size = (unsigned int)(orig_layer_it->last_neuron - orig_layer_it->first_neuron);
        copy_layer_it->first_neuron = NULL;
        copy_layer_it->last_neuron = copy_layer_it->first_neuron + layer_size;
        copy->total_neurons += layer_size;
    }
    copy->num_input = orig->num_input;
    copy->num_output = orig->num_output;


    /* copy scale parameters, when used */
#ifndef FIXEDFANN
    if (orig->scale_mean_in != NULL)
    {
        fann_allocate_scale(copy);
        for (i=0; i < orig->num_input ; i++) {
            copy->scale_mean_in[i] = orig->scale_mean_in[i];
            copy->scale_deviation_in[i] = orig->scale_deviation_in[i];
            copy->scale_new_min_in[i] = orig->scale_new_min_in[i];
            copy->scale_factor_in[i] = orig->scale_factor_in[i];
        }
        for (i=0; i < orig->num_output ; i++) {
            copy->scale_mean_out[i] = orig->scale_mean_out[i];
            copy->scale_deviation_out[i] = orig->scale_deviation_out[i];
            copy->scale_new_min_out[i] = orig->scale_new_min_out[i];
            copy->scale_factor_out[i] = orig->scale_factor_out[i];
        }
    }
#endif

    /* copy the neurons */
    fann_allocate_neurons(copy);
    if (copy->errno_f == FANN_E_CANT_ALLOCATE_MEM)
    {
        fann_destroy(copy);
        return NULL;
    }
    layer_size = (unsigned int)((orig->last_layer-1)->last_neuron - (orig->last_layer-1)->first_neuron);
    memcpy(copy->output,orig->output, layer_size * sizeof(fann_type));

    last_neuron = (orig->last_layer - 1)->last_neuron;
    for (orig_neuron_it = orig->first_layer->first_neuron, copy_neuron_it = copy->first_layer->first_neuron;
            orig_neuron_it != last_neuron; orig_neuron_it++, copy_neuron_it++)
    {
        memcpy(copy_neuron_it,orig_neuron_it,sizeof(struct fann_neuron));
    }
 /* copy the connections */
    copy->total_connections = orig->total_connections;
    fann_allocate_connections(copy);
    if (copy->errno_f == FANN_E_CANT_ALLOCATE_MEM)
    {
        fann_destroy(copy);
        return NULL;
    }

    orig_first_neuron = orig->first_layer->first_neuron;
    copy_first_neuron = copy->first_layer->first_neuron;
    for (i=0; i < orig->total_connections; i++)
    {
        copy->weights[i] = orig->weights[i];
        input_neuron = (unsigned int)(orig->connections[i] - orig_first_neuron);
        copy->connections[i] = copy_first_neuron + input_neuron;
    }

    if (orig->train_slopes)
    {
        copy->train_slopes = (fann_type *) malloc(copy->total_connections_allocated * sizeof(fann_type));
        if (copy->train_slopes == NULL)
        {
            // fann_error((struct fann_error *) orig, FANN_E_CANT_ALLOCATE_MEM);
            printf("Error: fann_copy(): FANN_E_CANT_ALLOCATE_MEM\n");
            fann_destroy(copy);
            return NULL;
        }
        memcpy(copy->train_slopes,orig->train_slopes,copy->total_connections_allocated * sizeof(fann_type));
    }

    if (orig->prev_steps)
    {
        copy->prev_steps = (fann_type *) malloc(copy->total_connections_allocated * sizeof(fann_type));
        if (copy->prev_steps == NULL)
        {
            // fann_error((struct fann_error *) orig, FANN_E_CANT_ALLOCATE_MEM);
            printf("Error: fann_copy(): FANN_E_CANT_ALLOCATE_MEM\n");
            fann_destroy(copy);
            return NULL;
        }
        memcpy(copy->prev_steps, orig->prev_steps, copy->total_connections_allocated * sizeof(fann_type));
    }

    if (orig->prev_train_slopes)
    {
        copy->prev_train_slopes = (fann_type *) malloc(copy->total_connections_allocated * sizeof(fann_type));
        if (copy->prev_train_slopes == NULL)
        {
            // fann_error((struct fann_error *) orig, FANN_E_CANT_ALLOCATE_MEM);
            printf("Error: fann_copy(): FANN_E_CANT_ALLOCATE_MEM\n");
            fann_destroy(copy);
            return NULL;
        }
        memcpy(copy->prev_train_slopes,orig->prev_train_slopes, copy->total_connections_allocated * sizeof(fann_type));
    }

    if (orig->prev_weights_deltas)
    {
        copy->prev_weights_deltas = (fann_type *) malloc(copy->total_connections_allocated * sizeof(fann_type));
        if(copy->prev_weights_deltas == NULL)
        {
            // fann_error((struct fann_error *) orig, FANN_E_CANT_ALLOCATE_MEM);
            printf("Error: fann_copy(): FANN_E_CANT_ALLOCATE_MEM\n");
            fann_destroy(copy);
            return NULL;
        }
        memcpy(copy->prev_weights_deltas, orig->prev_weights_deltas,copy->total_connections_allocated * sizeof(fann_type));
    }

    return copy;
}

FANN_EXTERNAL void FANN_API fann_print_connections(struct fann *ann)
{
    struct fann_layer *layer_it;
    struct fann_neuron *neuron_it;
    unsigned int i;
    int value;
    char *neurons;
    unsigned int num_neurons = fann_get_total_neurons(ann) - fann_get_num_output(ann);

    neurons = (char *) malloc(num_neurons + 1);
    if(neurons == NULL)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_print_connections(): FANN_E_CANT_ALLOCATE_MEM\n");
        return;
    }
    neurons[num_neurons] = 0;

    printf("Layer / Neuron ");
    for(i = 0; i < num_neurons; i++)
    {
        printf("%d", i % 10);
    }
    printf("\n");

    for(layer_it = ann->first_layer + 1; layer_it != ann->last_layer; layer_it++)
    {
        for(neuron_it = layer_it->first_neuron; neuron_it != layer_it->last_neuron; neuron_it++)
        {

            memset(neurons, (int) '.', num_neurons);
            for(i = neuron_it->first_con; i < neuron_it->last_con; i++)
            {
                if(ann->weights[i] < 0)
                {
#ifdef FIXEDFANN
                    value = (int) ((ann->weights[i] / (double) ann->multiplier) - 0.5);
#else
                    value = (int) ((ann->weights[i]) - 0.5);
#endif
                    if(value < -25)
                        value = -25;
                    neurons[ann->connections[i] - ann->first_layer->first_neuron] = (char)('a' - value);
                }
                else
                {
#ifdef FIXEDFANN
                    value = (int) ((ann->weights[i] / (double) ann->multiplier) + 0.5);
#else
                    value = (int) ((ann->weights[i]) + 0.5);
#endif
                    if(value > 25)
                        value = 25;
                    neurons[ann->connections[i] - ann->first_layer->first_neuron] = (char)('A' + value);
                }
            }
            printf("L %3d / N %4d %s\n", (int)(layer_it - ann->first_layer),
                   (int)(neuron_it - ann->first_layer->first_neuron), neurons);
        }
    }

    free(neurons);
}

/* Initialize the weights using Widrow + Nguyen's algorithm.
*/
FANN_EXTERNAL void FANN_API fann_init_weights(struct fann *ann, struct fann_train_data *train_data)
{
    fann_type smallest_inp, largest_inp;
    unsigned int dat = 0, elem, num_connect, num_hidden_neurons;
    struct fann_layer *layer_it;
    struct fann_neuron *neuron_it, *last_neuron, *bias_neuron;

#ifdef FIXEDFANN
    unsigned int multiplier = ann->multiplier;
#endif
    float scale_factor;

    for(smallest_inp = largest_inp = train_data->input[0][0]; dat < train_data->num_data; dat++)
    {
        for(elem = 0; elem < train_data->num_input; elem++)
        {
            if(train_data->input[dat][elem] < smallest_inp)
                smallest_inp = train_data->input[dat][elem];
            if(train_data->input[dat][elem] > largest_inp)
                largest_inp = train_data->input[dat][elem];
        }
    }

    num_hidden_neurons = (unsigned int)(
        ann->total_neurons - (ann->num_input + ann->num_output +
                              (ann->last_layer - ann->first_layer)));
    scale_factor =
        (float) (pow
                 ((double) (0.7f * (double) num_hidden_neurons),
                  (double) (1.0f / (double) ann->num_input)) / (double) (largest_inp -
                                                                         smallest_inp));

#ifdef DEBUG
    printf("Initializing weights with scale factor %f\n", scale_factor);
#endif
    bias_neuron = ann->first_layer->last_neuron - 1;
    for(layer_it = ann->first_layer + 1; layer_it != ann->last_layer; layer_it++)
    {
        last_neuron = layer_it->last_neuron;

        if(ann->network_type == FANN_NETTYPE_LAYER)
        {
            bias_neuron = (layer_it - 1)->last_neuron - 1;
        }

        for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
        {
            for(num_connect = neuron_it->first_con; num_connect < neuron_it->last_con;
                num_connect++)
            {
                if(bias_neuron == ann->connections[num_connect])
                {
#ifdef FIXEDFANN
                    ann->weights[num_connect] =
                        (fann_type) fann_rand(-scale_factor, scale_factor * multiplier);
#else
                    ann->weights[num_connect] = (fann_type) fann_rand(-scale_factor, scale_factor);
#endif
                }
                else
                {
#ifdef FIXEDFANN
                    ann->weights[num_connect] = (fann_type) fann_rand(0, scale_factor * multiplier);
#else
                    ann->weights[num_connect] = (fann_type) fann_rand(0, scale_factor);
#endif
                }
            }
        }
    }

#ifndef FIXEDFANN
    if(ann->prev_train_slopes != NULL)
    {
        fann_clear_train_arrays(ann);
    }
#endif
}

FANN_EXTERNAL void FANN_API fann_print_parameters(struct fann *ann)
{
    struct fann_layer *layer_it;
#ifndef FIXEDFANN
    unsigned int i;
#endif

    printf("Input layer                          :%4d neurons, 1 bias\n", ann->num_input);
    for(layer_it = ann->first_layer + 1; layer_it != ann->last_layer - 1; layer_it++)
    {
        if(ann->network_type == FANN_NETTYPE_SHORTCUT)
        {
            printf("  Hidden layer                       :%4d neurons, 0 bias\n",
                   (int)(layer_it->last_neuron - layer_it->first_neuron));
        }
        else
        {
            printf("  Hidden layer                       :%4d neurons, 1 bias\n",
                   (int)(layer_it->last_neuron - layer_it->first_neuron - 1));
        }
    }
    printf("Output layer                         :%4d neurons\n", ann->num_output);
    printf("Total neurons and biases             :%4d\n", fann_get_total_neurons(ann));
    printf("Total connections                    :%4d\n", ann->total_connections);
    printf("Connection rate                      :%8.3f\n", ann->connection_rate);
    printf("Network type                         :   %s\n", FANN_NETTYPE_NAMES[ann->network_type]);
#ifdef FIXEDFANN
    printf("Decimal point                        :%4d\n", ann->decimal_point);
    printf("Multiplier                           :%4d\n", ann->multiplier);
#else
    printf("Training algorithm                   :   %s\n", FANN_TRAIN_NAMES[ann->training_algorithm]);
    printf("Training error function              :   %s\n", FANN_ERRORFUNC_NAMES[ann->train_error_function]);
    printf("Training stop function               :   %s\n", FANN_STOPFUNC_NAMES[ann->train_stop_function]);
#endif
#ifdef FIXEDFANN
    printf("Bit fail limit                       :%4d\n", ann->bit_fail_limit);
#else
    printf("Bit fail limit                       :%8.3f\n", ann->bit_fail_limit);
    printf("Learning rate                        :%8.3f\n", ann->learning_rate);
    printf("Learning momentum                    :%8.3f\n", ann->learning_momentum);
    printf("Quickprop decay                      :%11.6f\n", ann->quickprop_decay);
    printf("Quickprop mu                         :%8.3f\n", ann->quickprop_mu);
    printf("RPROP increase factor                :%8.3f\n", ann->rprop_increase_factor);
    printf("RPROP decrease factor                :%8.3f\n", ann->rprop_decrease_factor);
    printf("RPROP delta min                      :%8.3f\n", ann->rprop_delta_min);
    printf("RPROP delta max                      :%8.3f\n", ann->rprop_delta_max);
    printf("Cascade output change fraction       :%11.6f\n", ann->cascade_output_change_fraction);
    printf("Cascade candidate change fraction    :%11.6f\n", ann->cascade_candidate_change_fraction);
    printf("Cascade output stagnation epochs     :%4d\n", ann->cascade_output_stagnation_epochs);
    printf("Cascade candidate stagnation epochs  :%4d\n", ann->cascade_candidate_stagnation_epochs);
    printf("Cascade max output epochs            :%4d\n", ann->cascade_max_out_epochs);
    printf("Cascade min output epochs            :%4d\n", ann->cascade_min_out_epochs);
    printf("Cascade max candidate epochs         :%4d\n", ann->cascade_max_cand_epochs);
    printf("Cascade min candidate epochs         :%4d\n", ann->cascade_min_cand_epochs);
    printf("Cascade weight multiplier            :%8.3f\n", ann->cascade_weight_multiplier);
    printf("Cascade candidate limit              :%8.3f\n", ann->cascade_candidate_limit);
    for(i = 0; i < ann->cascade_activation_functions_count; i++)
        printf("Cascade activation functions[%d]      :   %s\n", i,
            FANN_ACTIVATIONFUNC_NAMES[ann->cascade_activation_functions[i]]);
    for(i = 0; i < ann->cascade_activation_steepnesses_count; i++)
        printf("Cascade activation steepnesses[%d]    :%8.3f\n", i,
            ann->cascade_activation_steepnesses[i]);
        
    printf("Cascade candidate groups             :%4d\n", ann->cascade_num_candidate_groups);
    printf("Cascade no. of candidates            :%4d\n", fann_get_cascade_num_candidates(ann));
    
    /* TODO: dump scale parameters */
#endif
}

FANN_GET(unsigned int, num_input)
FANN_GET(unsigned int, num_output)

FANN_EXTERNAL unsigned int FANN_API fann_get_total_neurons(struct fann *ann)
{
    if(ann->network_type)
    {
        return ann->total_neurons;
    }
    else
    {
        /* -1, because there is always an unused bias neuron in the last layer */
        return ann->total_neurons - 1;
    }
}

FANN_GET(unsigned int, total_connections)

FANN_EXTERNAL enum fann_nettype_enum FANN_API fann_get_network_type(struct fann *ann)
{
    /* Currently two types: LAYER = 0, SHORTCUT = 1 */
    /* Enum network_types must be set to match the return values  */
    return ann->network_type;
}

FANN_EXTERNAL float FANN_API fann_get_connection_rate(struct fann *ann)
{
    return ann->connection_rate;
}

FANN_EXTERNAL unsigned int FANN_API fann_get_num_layers(struct fann *ann)
{
    return (unsigned int)(ann->last_layer - ann->first_layer);
}

FANN_EXTERNAL void FANN_API fann_get_layer_array(struct fann *ann, unsigned int *layers)
{
    struct fann_layer *layer_it;

    for (layer_it = ann->first_layer; layer_it != ann->last_layer; layer_it++) {
        unsigned int count = (unsigned int)(layer_it->last_neuron - layer_it->first_neuron);
        /* Remove the bias from the count of neurons. */
        switch (fann_get_network_type(ann)) {
            case FANN_NETTYPE_LAYER: {
                --count;
                break;
            }
            case FANN_NETTYPE_SHORTCUT: {
                /* The bias in the first layer is reused for all layers */
                if (layer_it == ann->first_layer)
                    --count;
                break;
            }
            default: {
                /* Unknown network type, assume no bias present  */
                break;
            }
        }
        *layers++ = count;
    }
}

FANN_EXTERNAL void FANN_API fann_get_bias_array(struct fann *ann, unsigned int *bias)
{
    struct fann_layer *layer_it;

    for (layer_it = ann->first_layer; layer_it != ann->last_layer; ++layer_it, ++bias) {
        switch (fann_get_network_type(ann)) {
            case FANN_NETTYPE_LAYER: {
                /* Report one bias in each layer except the last */
                if (layer_it != ann->last_layer-1)
                    *bias = 1;
                else
                    *bias = 0;
                break;
            }
            case FANN_NETTYPE_SHORTCUT: {
                /* The bias in the first layer is reused for all layers */
                if (layer_it == ann->first_layer)
                    *bias = 1;
                else
                    *bias = 0;
                break;
            }
            default: {
                /* Unknown network type, assume no bias present  */
                *bias = 0;
                break;
            }
        }
    }
}

FANN_EXTERNAL void FANN_API fann_get_connection_array(struct fann *ann, struct fann_connection *connections)
{
    struct fann_neuron *first_neuron;
    struct fann_layer *layer_it;
    struct fann_neuron *neuron_it;
    unsigned int idx;
    unsigned int source_index;
    unsigned int destination_index;

    first_neuron = ann->first_layer->first_neuron;

    source_index = 0;
    destination_index = 0;
    
    /* The following assumes that the last unused bias has no connections */

    /* for each layer */
    for(layer_it = ann->first_layer; layer_it != ann->last_layer; layer_it++){
        /* for each neuron */
        for(neuron_it = layer_it->first_neuron; neuron_it != layer_it->last_neuron; neuron_it++){
            /* for each connection */
            for (idx = neuron_it->first_con; idx < neuron_it->last_con; idx++){
                /* Assign the source, destination and weight */
                connections->from_neuron = (unsigned int)(ann->connections[source_index] - first_neuron);
                connections->to_neuron = destination_index;
                connections->weight = ann->weights[source_index];

                connections++;
                source_index++;
            }
            destination_index++;
        }
    }
}

FANN_EXTERNAL void FANN_API fann_set_weight_array(struct fann *ann,
    struct fann_connection *connections, unsigned int num_connections)
{
    unsigned int idx;

    for (idx = 0; idx < num_connections; idx++) {
        fann_set_weight(ann, connections[idx].from_neuron,
            connections[idx].to_neuron, connections[idx].weight);
    }
}

FANN_EXTERNAL void FANN_API fann_set_weight(struct fann *ann,
    unsigned int from_neuron, unsigned int to_neuron, fann_type weight)
{
    struct fann_neuron *first_neuron;
    struct fann_layer *layer_it;
    struct fann_neuron *neuron_it;
    unsigned int idx;
    unsigned int source_index;
    unsigned int destination_index;

    first_neuron = ann->first_layer->first_neuron;

    source_index = 0;
    destination_index = 0;

    /* Find the connection, simple brute force search through the network
       for one or more connections that match to minimize datastructure dependencies.
       Nothing is done if the connection does not already exist in the network. */

    /* for each layer */
    for(layer_it = ann->first_layer; layer_it != ann->last_layer; layer_it++){
        /* for each neuron */
        for(neuron_it = layer_it->first_neuron; neuron_it != layer_it->last_neuron; neuron_it++){
            /* for each connection */
            for (idx = neuron_it->first_con; idx < neuron_it->last_con; idx++){
                /* If the source and destination neurons match, assign the weight */
                if (((int)from_neuron == ann->connections[source_index] - first_neuron) &&
                    (to_neuron == destination_index))
                {
                    ann->weights[source_index] = weight;
                }
                source_index++;
            }
            destination_index++;
        }
    }
}

FANN_EXTERNAL void FANN_API fann_get_weights(struct fann *ann, fann_type *weights)
{
    memcpy(weights, ann->weights, sizeof(fann_type)*ann->total_connections);
}

FANN_EXTERNAL void FANN_API fann_set_weights(struct fann *ann, fann_type *weights)
{
    memcpy(ann->weights, weights, sizeof(fann_type)*ann->total_connections);
}

FANN_GET_SET(void *, user_data)

#ifdef FIXEDFANN

FANN_GET(unsigned int, decimal_point)
FANN_GET(unsigned int, multiplier)

/* INTERNAL FUNCTION
   Adjust the steepwise functions (if used)
*/
void fann_update_stepwise(struct fann *ann)
{
    unsigned int i = 0;

    /* Calculate the parameters for the stepwise linear
     * sigmoid function fixed point.
     * Using a rewritten sigmoid function.
     * results 0.005, 0.05, 0.25, 0.75, 0.95, 0.995
     */
    ann->sigmoid_results[0] = fann_max((fann_type) (ann->multiplier / 200.0 + 0.5), 1);
    ann->sigmoid_results[1] = fann_max((fann_type) (ann->multiplier / 20.0 + 0.5), 1);
    ann->sigmoid_results[2] = fann_max((fann_type) (ann->multiplier / 4.0 + 0.5), 1);
    ann->sigmoid_results[3] = fann_min(ann->multiplier - (fann_type) (ann->multiplier / 4.0 + 0.5), ann->multiplier - 1);
    ann->sigmoid_results[4] = fann_min(ann->multiplier - (fann_type) (ann->multiplier / 20.0 + 0.5), ann->multiplier - 1);
    ann->sigmoid_results[5] = fann_min(ann->multiplier - (fann_type) (ann->multiplier / 200.0 + 0.5), ann->multiplier - 1);

    ann->sigmoid_symmetric_results[0] = fann_max((fann_type) ((ann->multiplier / 100.0) - ann->multiplier - 0.5),
                                                 (fann_type) (1 - (fann_type) ann->multiplier));
    ann->sigmoid_symmetric_results[1] = fann_max((fann_type) ((ann->multiplier / 10.0) - ann->multiplier - 0.5),
                                                 (fann_type) (1 - (fann_type) ann->multiplier));
    ann->sigmoid_symmetric_results[2] = fann_max((fann_type) ((ann->multiplier / 2.0) - ann->multiplier - 0.5),
                                                 (fann_type) (1 - (fann_type) ann->multiplier));
    ann->sigmoid_symmetric_results[3] = fann_min(ann->multiplier - (fann_type) (ann->multiplier / 2.0 + 0.5),
                                                 ann->multiplier - 1);
    ann->sigmoid_symmetric_results[4] = fann_min(ann->multiplier - (fann_type) (ann->multiplier / 10.0 + 0.5),
                                                 ann->multiplier - 1);
    ann->sigmoid_symmetric_results[5] = fann_min(ann->multiplier - (fann_type) (ann->multiplier / 100.0 + 1.0),
                                                 ann->multiplier - 1);

    for(i = 0; i < 6; i++)
    {
        ann->sigmoid_values[i] =
            (fann_type) (((log(ann->multiplier / (float) ann->sigmoid_results[i] - 1) *
                           (float) ann->multiplier) / -2.0) * (float) ann->multiplier);
        ann->sigmoid_symmetric_values[i] =
            (fann_type) (((log
                           ((ann->multiplier -
                             (float) ann->sigmoid_symmetric_results[i]) /
                            ((float) ann->sigmoid_symmetric_results[i] +
                             ann->multiplier)) * (float) ann->multiplier) / -2.0) *
                         (float) ann->multiplier);
    }
}
#endif


/* INTERNAL FUNCTION
   Allocates the main structure and sets some default values.
 */
struct fann *fann_allocate_structure(unsigned int num_layers)
{
    struct fann *ann;

    if(num_layers < 2)
    {
#ifdef DEBUG
        printf("less than 2 layers - ABORTING.\n");
#endif
        return NULL;
    }

    /* allocate and initialize the main network structure */
    ann = (struct fann *) malloc(sizeof(struct fann));
    if(ann == NULL)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_allocate_structure(): FANN_E_CANT_ALLOCATE_MEM\n");
        return NULL;
    }

    ann->errno_f = FANN_E_NO_ERROR;
    // ann->error_log = fann_default_error_log;
    ann->errstr = NULL;
    ann->learning_rate = 0.7f;
    ann->learning_momentum = 0.0;
    ann->total_neurons = 0;
    ann->total_connections = 0;
    ann->num_input = 0;
    ann->num_output = 0;
    ann->train_errors = NULL;
    ann->train_slopes = NULL;
    ann->prev_steps = NULL;
    ann->prev_train_slopes = NULL;
    ann->prev_weights_deltas = NULL;
    ann->training_algorithm = FANN_TRAIN_RPROP;
    ann->num_MSE = 0;
    ann->MSE_value = 0;
    ann->num_bit_fail = 0;
    ann->bit_fail_limit = (fann_type)0.35;
    ann->network_type = FANN_NETTYPE_LAYER;
    ann->train_error_function = FANN_ERRORFUNC_TANH;
    ann->train_stop_function = FANN_STOPFUNC_MSE;
    ann->callback = NULL;
    ann->user_data = NULL; /* User is responsible for deallocation */
    ann->weights = NULL;
    ann->connections = NULL;
    ann->output = NULL;
#ifndef FIXEDFANN
    ann->scale_mean_in = NULL;
    ann->scale_deviation_in = NULL;
    ann->scale_new_min_in = NULL;
    ann->scale_factor_in = NULL;
    ann->scale_mean_out = NULL;
    ann->scale_deviation_out = NULL;
    ann->scale_new_min_out = NULL;
    ann->scale_factor_out = NULL;
#endif  
    
    /* variables used for cascade correlation (reasonable defaults) */
    ann->cascade_output_change_fraction = 0.01f;
    ann->cascade_candidate_change_fraction = 0.01f;
    ann->cascade_output_stagnation_epochs = 12;
    ann->cascade_candidate_stagnation_epochs = 12;
    ann->cascade_num_candidate_groups = 2;
    ann->cascade_weight_multiplier = (fann_type)0.4;
    ann->cascade_candidate_limit = (fann_type)1000.0;
    ann->cascade_max_out_epochs = 150;
    ann->cascade_max_cand_epochs = 150;
    ann->cascade_min_out_epochs = 50;
    ann->cascade_min_cand_epochs = 50;
    ann->cascade_candidate_scores = NULL;
    ann->cascade_activation_functions_count = 10;
    ann->cascade_activation_functions = 
        (enum fann_activationfunc_enum *)calloc(ann->cascade_activation_functions_count, 
                               sizeof(enum fann_activationfunc_enum));
    if(ann->cascade_activation_functions == NULL)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_allocate_structure(): FANN_E_CANT_ALLOCATE_MEM\n");
        free(ann);
        return NULL;
    }
                               
    ann->cascade_activation_functions[0] = FANN_SIGMOID;
    ann->cascade_activation_functions[1] = FANN_SIGMOID_SYMMETRIC;
    ann->cascade_activation_functions[2] = FANN_GAUSSIAN;
    ann->cascade_activation_functions[3] = FANN_GAUSSIAN_SYMMETRIC;
    ann->cascade_activation_functions[4] = FANN_ELLIOT;
    ann->cascade_activation_functions[5] = FANN_ELLIOT_SYMMETRIC;
    ann->cascade_activation_functions[6] = FANN_SIN_SYMMETRIC;
    ann->cascade_activation_functions[7] = FANN_COS_SYMMETRIC;
    ann->cascade_activation_functions[8] = FANN_SIN;
    ann->cascade_activation_functions[9] = FANN_COS;

    ann->cascade_activation_steepnesses_count = 4;
    ann->cascade_activation_steepnesses = (fann_type *)calloc(ann->cascade_activation_steepnesses_count, sizeof(fann_type));
    if(ann->cascade_activation_steepnesses == NULL)
    {
        fann_safe_free(ann->cascade_activation_functions);
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_allocate_structure(): FANN_E_CANT_ALLOCATE_MEM\n");
        free(ann);
        return NULL;
    }
    
    ann->cascade_activation_steepnesses[0] = (fann_type)0.25;
    ann->cascade_activation_steepnesses[1] = (fann_type)0.5;
    ann->cascade_activation_steepnesses[2] = (fann_type)0.75;
    ann->cascade_activation_steepnesses[3] = (fann_type)1.0;

    /* Variables for use with with Quickprop training (reasonable defaults) */
    ann->quickprop_decay = -0.0001f;
    ann->quickprop_mu = 1.75;

    /* Variables for use with with RPROP training (reasonable defaults) */
    ann->rprop_increase_factor = 1.2f;
    ann->rprop_decrease_factor = 0.5;
    ann->rprop_delta_min = 0.0;
    ann->rprop_delta_max = 50.0;
    ann->rprop_delta_zero = 0.1f;
    
    /* Variables for use with SARPROP training (reasonable defaults) */
    ann->sarprop_weight_decay_shift = -6.644f;
    ann->sarprop_step_error_threshold_factor = 0.1f;
    ann->sarprop_step_error_shift = 1.385f;
    ann->sarprop_temperature = 0.015f;
    ann->sarprop_epoch = 0;
 
    // fann_init_error_data((struct fann_error *) ann);

#ifdef FIXEDFANN
    /* these values are only boring defaults, and should really
     * never be used, since the real values are always loaded from a file. */
    ann->decimal_point = 8;
    ann->multiplier = 256;
#endif

    /* allocate room for the layers */
    ann->first_layer = (struct fann_layer *) calloc(num_layers, sizeof(struct fann_layer));
    if(ann->first_layer == NULL)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_allocate_structure(): FANN_E_CANT_ALLOCATE_MEM\n");
        free(ann);
        return NULL;
    }

    ann->last_layer = ann->first_layer + num_layers;

    return ann;
}

/* INTERNAL FUNCTION
   Allocates room for the scaling parameters.
 */
int fann_allocate_scale(struct fann *ann)
{
    /* todo this should only be allocated when needed */
#ifndef FIXEDFANN
    unsigned int i = 0;
#define SCALE_ALLOCATE( what, where, default_value )                        \
        ann->what##_##where = (float *)calloc(                              \
            ann->num_##where##put,                                          \
            sizeof( float )                                                 \
            );                                                              \
        if( ann->what##_##where == NULL )                                   \
        {                                                                   \
            printf("Error: fann_allocate_scale(): FANN_E_CANT_ALLOCATE_MEM\n"); \
            fann_destroy( ann );                                            \
            return 1;                                                       \
        }                                                                   \
        for( i = 0; i < ann->num_##where##put; i++ )                        \
            ann->what##_##where[ i ] = ( default_value );

    SCALE_ALLOCATE( scale_mean,     in,     0.0 )
    SCALE_ALLOCATE( scale_deviation,    in,     1.0 )
    SCALE_ALLOCATE( scale_new_min,  in,     -1.0 )
    SCALE_ALLOCATE( scale_factor,       in,     1.0 )

    SCALE_ALLOCATE( scale_mean,     out,    0.0 )
    SCALE_ALLOCATE( scale_deviation,    out,    1.0 )
    SCALE_ALLOCATE( scale_new_min,  out,    -1.0 )
    SCALE_ALLOCATE( scale_factor,       out,    1.0 )
#undef SCALE_ALLOCATE
#endif  
    return 0;
}

/* INTERNAL FUNCTION
   Allocates room for the neurons.
 */
void fann_allocate_neurons(struct fann *ann)
{
    struct fann_layer *layer_it;
    struct fann_neuron *neurons;
    unsigned int num_neurons_so_far = 0;
    unsigned int num_neurons = 0;

    /* all the neurons is allocated in one long array (calloc clears mem) */
    neurons = (struct fann_neuron *) calloc(ann->total_neurons, sizeof(struct fann_neuron));
    ann->total_neurons_allocated = ann->total_neurons;

    if(neurons == NULL)
    {
        // fann_error((struct fann_error *) ann, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_allocate_neurons(): FANN_E_CANT_ALLOCATE_MEM\n");
        return;
    }

    for(layer_it = ann->first_layer; layer_it != ann->last_layer; layer_it++)
    {
        num_neurons = (unsigned int)(layer_it->last_neuron - layer_it->first_neuron);
        layer_it->first_neuron = neurons + num_neurons_so_far;
        layer_it->last_neuron = layer_it->first_neuron + num_neurons;
        num_neurons_so_far += num_neurons;
    }

    ann->output = (fann_type *) calloc(num_neurons, sizeof(fann_type));
    if(ann->output == NULL)
    {
        // fann_error((struct fann_error *) ann, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_allocate_neurons(): FANN_E_CANT_ALLOCATE_MEM\n");
        return;
    }
}

/* INTERNAL FUNCTION
   Allocate room for the connections.
 */
void fann_allocate_connections(struct fann *ann)
{
    ann->weights = (fann_type *) calloc(ann->total_connections, sizeof(fann_type));
    if(ann->weights == NULL)
    {
        // fann_error((struct fann_error *) ann, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_allocate_connections(): FANN_E_CANT_ALLOCATE_MEM\n");
        return;
    }
    ann->total_connections_allocated = ann->total_connections;

    /* TODO make special cases for all places where the connections
     * is used, so that it is not needed for fully connected networks.
     */
    ann->connections =
        (struct fann_neuron **) calloc(ann->total_connections_allocated,
                                       sizeof(struct fann_neuron *));
    if(ann->connections == NULL)
    {
        // fann_error((struct fann_error *) ann, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_allocate_connections(): FANN_E_CANT_ALLOCATE_MEM\n");
        return;
    }
}


FANN_EXTERNAL unsigned int FANN_API fann_get_cascade_num_candidates(struct fann *ann)
{
    return ann->cascade_activation_functions_count *
        ann->cascade_activation_steepnesses_count *
        ann->cascade_num_candidate_groups;
}

// FANN_GET_SET(float, cascade_output_change_fraction)
// FANN_GET_SET(unsigned int, cascade_output_stagnation_epochs)
// FANN_GET_SET(float, cascade_candidate_change_fraction)
// FANN_GET_SET(unsigned int, cascade_candidate_stagnation_epochs)
// FANN_GET_SET(unsigned int, cascade_num_candidate_groups)
// FANN_GET_SET(fann_type, cascade_weight_multiplier)
// FANN_GET_SET(fann_type, cascade_candidate_limit)
// FANN_GET_SET(unsigned int, cascade_max_out_epochs)
// FANN_GET_SET(unsigned int, cascade_max_cand_epochs)
// FANN_GET_SET(unsigned int, cascade_min_out_epochs)
// FANN_GET_SET(unsigned int, cascade_min_cand_epochs)

// FANN_GET_SET(enum fann_train_enum, training_algorithm)
// FANN_GET_SET(float, learning_rate)

// FANN_EXTERNAL void FANN_API fann_set_activation_function_hidden(struct fann *ann, enum fann_activationfunc_enum activation_function)
// {
//     struct fann_neuron *last_neuron, *neuron_it;
//     struct fann_layer *layer_it;
//     struct fann_layer *last_layer = ann->last_layer - 1;    ///* -1 to not update the output layer */

//     for(layer_it = ann->first_layer + 1; layer_it != last_layer; layer_it++)
//     {
//         last_neuron = layer_it->last_neuron;
//         for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
//         {
//             neuron_it->activation_function = activation_function;
//         }
//     }
// }

// FANN_EXTERNAL struct fann_layer* FANN_API fann_get_layer(struct fann *ann, int layer)
// {
//     if(layer <= 0 || layer >= (ann->last_layer - ann->first_layer))
//     {
//         // fann_error((struct fann_error *) ann, FANN_E_INDEX_OUT_OF_BOUND, layer);
//         printf("Error: fann_get_layer(): FANN_E_CANT_ALLOCATE_MEM\n");
//         return NULL;
//     }
    
//     return ann->first_layer + layer;    
// }

// FANN_EXTERNAL struct fann_neuron* FANN_API fann_get_neuron_layer(struct fann *ann, struct fann_layer* layer, int neuron)
// {
//     if(neuron >= (layer->last_neuron - layer->first_neuron))
//     {
//         // fann_error((struct fann_error *) ann, FANN_E_INDEX_OUT_OF_BOUND, neuron);
//         printf("Error: fann_get_neuron_layer(): FANN_E_CANT_ALLOCATE_MEM\n");
//         return NULL;    
//     }
    
//     return layer->first_neuron + neuron;
// }

// FANN_EXTERNAL struct fann_neuron* FANN_API fann_get_neuron(struct fann *ann, unsigned int layer, int neuron)
// {
//     struct fann_layer *layer_it = fann_get_layer(ann, layer);
//     if(layer_it == NULL)
//         return NULL;
//     return fann_get_neuron_layer(ann, layer_it, neuron);
// }

// FANN_EXTERNAL enum fann_activationfunc_enum FANN_API fann_get_activation_function(struct fann *ann, int layer, int neuron)
// {
//     struct fann_neuron* neuron_it = fann_get_neuron(ann, layer, neuron);
//     if (neuron_it == NULL)
//     {
//         return (enum fann_activationfunc_enum)-1; /* layer or neuron out of bounds */
//     }
//     else
//     {
//         return neuron_it->activation_function;
//     }
// }

// FANN_EXTERNAL void FANN_API fann_set_activation_function(struct fann *ann,
//                                                                 enum fann_activationfunc_enum
//                                                                 activation_function,
//                                                                 int layer,
//                                                                 int neuron)
// {
//     struct fann_neuron* neuron_it = fann_get_neuron(ann, layer, neuron);
//     if(neuron_it == NULL)
//         return;

//     neuron_it->activation_function = activation_function;
// }

// FANN_EXTERNAL void FANN_API fann_set_activation_function_layer(struct fann *ann,
//                                                                 enum fann_activationfunc_enum
//                                                                 activation_function,
//                                                                 int layer)
// {
//     struct fann_neuron *last_neuron, *neuron_it;
//     struct fann_layer *layer_it = fann_get_layer(ann, layer);
    
//     if(layer_it == NULL)
//         return;

//     last_neuron = layer_it->last_neuron;
//     for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
//     {
//         neuron_it->activation_function = activation_function;
//     }
// }


// FANN_EXTERNAL void FANN_API fann_set_activation_function_output(struct fann *ann,
//                                                                 enum fann_activationfunc_enum activation_function)
// {
//     struct fann_neuron *last_neuron, *neuron_it;
//     struct fann_layer *last_layer = ann->last_layer - 1;

//     last_neuron = last_layer->last_neuron;
//     for(neuron_it = last_layer->first_neuron; neuron_it != last_neuron; neuron_it++)
//     {
//         neuron_it->activation_function = activation_function;
//     }
// }

// FANN_EXTERNAL void FANN_API fann_set_activation_steepness_hidden(struct fann *ann,
//                                                                  fann_type steepness)
// {
//     struct fann_neuron *last_neuron, *neuron_it;
//     struct fann_layer *layer_it;
//     struct fann_layer *last_layer = ann->last_layer - 1;    /* -1 to not update the output layer */

//     for(layer_it = ann->first_layer + 1; layer_it != last_layer; layer_it++)
//     {
//         last_neuron = layer_it->last_neuron;
//         for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
//         {
//             neuron_it->activation_steepness = steepness;
//         }
//     }
// }

// FANN_EXTERNAL fann_type FANN_API fann_get_activation_steepness(struct fann *ann, int layer, int neuron)
// {
//     struct fann_neuron* neuron_it = fann_get_neuron(ann, layer, neuron);
//     if(neuron_it == NULL)
//     {
//         return -1; /* layer or neuron out of bounds */
//     }
//     else
//     {
//         return neuron_it->activation_steepness;
//     }
// }

// FANN_EXTERNAL void FANN_API fann_set_activation_steepness(struct fann *ann,
//                                                                 fann_type steepness,
//                                                                 int layer,
//                                                                 int neuron)
// {
//     struct fann_neuron* neuron_it = fann_get_neuron(ann, layer, neuron);
//     if(neuron_it == NULL)
//         return;

//     neuron_it->activation_steepness = steepness;
// }

// FANN_EXTERNAL void FANN_API fann_set_activation_steepness_layer(struct fann *ann,
//                                                                 fann_type steepness,
//                                                                 int layer)
// {
//     struct fann_neuron *last_neuron, *neuron_it;
//     struct fann_layer *layer_it = fann_get_layer(ann, layer);
    
//     if(layer_it == NULL)
//         return;

//     last_neuron = layer_it->last_neuron;
//     for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
//     {
//         neuron_it->activation_steepness = steepness;
//     }
// }

// FANN_EXTERNAL void FANN_API fann_set_activation_steepness_output(struct fann *ann,
//                                                                  fann_type steepness)
// {
//     struct fann_neuron *last_neuron, *neuron_it;
//     struct fann_layer *last_layer = ann->last_layer - 1;

//     last_neuron = last_layer->last_neuron;
//     for(neuron_it = last_layer->first_neuron; neuron_it != last_neuron; neuron_it++)
//     {
//         neuron_it->activation_steepness = steepness;
//     }
// }

// FANN_GET_SET(enum fann_errorfunc_enum, train_error_function)
// FANN_GET_SET(fann_callback_type, callback)
// FANN_GET_SET(float, quickprop_decay)
// FANN_GET_SET(float, quickprop_mu)
// FANN_GET_SET(float, rprop_increase_factor)
// FANN_GET_SET(float, rprop_decrease_factor)
// FANN_GET_SET(float, rprop_delta_min)
// FANN_GET_SET(float, rprop_delta_max)
// FANN_GET_SET(float, rprop_delta_zero)
// FANN_GET_SET(float, sarprop_weight_decay_shift)
// FANN_GET_SET(float, sarprop_step_error_threshold_factor)
// FANN_GET_SET(float, sarprop_step_error_shift)
// FANN_GET_SET(float, sarprop_temperature)
// FANN_GET_SET(enum fann_stopfunc_enum, train_stop_function)
// FANN_GET_SET(fann_type, bit_fail_limit)
// FANN_GET_SET(float, learning_momentum)




////////////////////////////////
//// From fann_train_data.c ////
////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * deallocate the train data structure. 
 */
FANN_EXTERNAL void FANN_API fann_destroy_train(struct fann_train_data *data)
{
    if(data == NULL)
        return;
    if(data->input != NULL)
        fann_safe_free(data->input[0]);
    if(data->output != NULL)
        fann_safe_free(data->output[0]);
    fann_safe_free(data->input);
    fann_safe_free(data->output);
    fann_safe_free(data);
}

/*
 * Test a set of training data and calculate the MSE 
 */
FANN_EXTERNAL float FANN_API fann_test_data(struct fann *ann, struct fann_train_data *data)
{
    unsigned int i;
    if(fann_check_input_output_sizes(ann, data) == -1)
        return 0;
    
    fann_reset_MSE(ann);

    for(i = 0; i != data->num_data; i++)
    {
        fann_test(ann, data->input[i], data->output[i]);
    }

    return fann_get_MSE(ann);
}

#ifndef FIXEDFANN

/*
 * Internal train function 
 */
float fann_train_epoch_quickprop(struct fann *ann, struct fann_train_data *data)
{
    unsigned int i;

    if(ann->prev_train_slopes == NULL)
    {
        fann_clear_train_arrays(ann);
    }

    fann_reset_MSE(ann);

    for(i = 0; i < data->num_data; i++)
    {
        fann_run(ann, data->input[i]);
        fann_compute_MSE(ann, data->output[i]);
        fann_backpropagate_MSE(ann);
        fann_update_slopes_batch(ann, ann->first_layer + 1, ann->last_layer - 1);
    }
    fann_update_weights_quickprop(ann, data->num_data, 0, ann->total_connections);

    return fann_get_MSE(ann);
}

/*
 * Internal train function 
 */
float fann_train_epoch_irpropm(struct fann *ann, struct fann_train_data *data)
{
    unsigned int i;

    if(ann->prev_train_slopes == NULL)
    {
        fann_clear_train_arrays(ann);
    }

    fann_reset_MSE(ann);

    for(i = 0; i < data->num_data; i++)
    {
        fann_run(ann, data->input[i]);
        fann_compute_MSE(ann, data->output[i]);
        fann_backpropagate_MSE(ann);
        fann_update_slopes_batch(ann, ann->first_layer + 1, ann->last_layer - 1);
    }

    fann_update_weights_irpropm(ann, 0, ann->total_connections);

    return fann_get_MSE(ann);
}

/*
 * Internal train function 
 */
float fann_train_epoch_sarprop(struct fann *ann, struct fann_train_data *data)
{
    unsigned int i;

    if(ann->prev_train_slopes == NULL)
    {
        fann_clear_train_arrays(ann);
    }

    fann_reset_MSE(ann);

    for(i = 0; i < data->num_data; i++)
    {
        fann_run(ann, data->input[i]);
        fann_compute_MSE(ann, data->output[i]);
        fann_backpropagate_MSE(ann);
        fann_update_slopes_batch(ann, ann->first_layer + 1, ann->last_layer - 1);
    }

    fann_update_weights_sarprop(ann, ann->sarprop_epoch, 0, ann->total_connections);

    ++(ann->sarprop_epoch);

    return fann_get_MSE(ann);
}

/*
 * Internal train function 
 */
float fann_train_epoch_batch(struct fann *ann, struct fann_train_data *data)
{
    unsigned int i;

    fann_reset_MSE(ann);

    for(i = 0; i < data->num_data; i++)
    {
        fann_run(ann, data->input[i]);
        fann_compute_MSE(ann, data->output[i]);
        fann_backpropagate_MSE(ann);
        fann_update_slopes_batch(ann, ann->first_layer + 1, ann->last_layer - 1);
    }

    fann_update_weights_batch(ann, data->num_data, 0, ann->total_connections);

    return fann_get_MSE(ann);
}

/*
 * Internal train function 
 */
float fann_train_epoch_incremental(struct fann *ann, struct fann_train_data *data)
{
    unsigned int i;

    fann_reset_MSE(ann);

    for(i = 0; i != data->num_data; i++)
    {
        fann_train(ann, data->input[i], data->output[i]);
    }

    return fann_get_MSE(ann);
}

/*
 * Train for one epoch with the selected training algorithm 
 */
FANN_EXTERNAL float FANN_API fann_train_epoch(struct fann *ann, struct fann_train_data *data)
{
    if(fann_check_input_output_sizes(ann, data) == -1)
        return 0;
    
    switch (ann->training_algorithm)
    {
    case FANN_TRAIN_QUICKPROP:
        return fann_train_epoch_quickprop(ann, data);
    case FANN_TRAIN_RPROP:
        return fann_train_epoch_irpropm(ann, data);
    case FANN_TRAIN_SARPROP:
        return fann_train_epoch_sarprop(ann, data);
    case FANN_TRAIN_BATCH:
        return fann_train_epoch_batch(ann, data);
    case FANN_TRAIN_INCREMENTAL:
        return fann_train_epoch_incremental(ann, data);
    }
    return 0;
}

FANN_EXTERNAL void FANN_API fann_train_on_data(struct fann *ann, struct fann_train_data *data,
                                               unsigned int max_epochs,
                                               unsigned int epochs_between_reports,
                                               float desired_error)
{
    float error;
    unsigned int i;
    int desired_error_reached;

#ifdef DEBUG
    printf("Training with %s\n", FANN_TRAIN_NAMES[ann->training_algorithm]);
#endif

    if(epochs_between_reports && ann->callback == NULL)
    {
        printf("Max epochs %8d. Desired error: %.10f.\n", max_epochs, desired_error);
    }

    for(i = 1; i <= max_epochs; i++)
    {
        /*
         * train 
         */
        error = fann_train_epoch(ann, data);
        desired_error_reached = fann_desired_error_reached(ann, desired_error);

        /*
         * print current output 
         */
        if(epochs_between_reports &&
           (i % epochs_between_reports == 0 || i == max_epochs || i == 1 ||
            desired_error_reached == 0))
        {
            if(ann->callback == NULL)
            {
                printf("Epochs     %8d. Current error: %.10f. Bit fail %d.\n", i, error,
                       ann->num_bit_fail);
            }
            else if(((*ann->callback)(ann, data, max_epochs, epochs_between_reports, 
                                      desired_error, i)) == -1)
            {
                /*
                 * you can break the training by returning -1 
                 */
                break;
            }
        }

        if(desired_error_reached == 0)
            break;
    }
}

#endif

/*
 * shuffles training data, randomizing the order 
 */
FANN_EXTERNAL void FANN_API fann_shuffle_train_data(struct fann_train_data *train_data)
{
    unsigned int dat = 0, elem, swap;
    fann_type temp;

    for(; dat < train_data->num_data; dat++)
    {
        /* Using SGX's random number generator */
        sgx_status_t sgx_ret = SGX_SUCCESS;
        unsigned char rand_buff[4];
        sgx_ret = sgx_read_rand(rand_buff, 4);
        int rand_num = (int)(rand_buff[0]) + 16*(int)(rand_buff[1]) + 16*16*(int)(rand_buff[2]) + 16*16*16*(int)(rand_buff[3]);
        swap = (unsigned int) (rand_num % train_data->num_data);

        if(swap != dat)
        {
            for(elem = 0; elem < train_data->num_input; elem++)
            {
                temp = train_data->input[dat][elem];
                train_data->input[dat][elem] = train_data->input[swap][elem];
                train_data->input[swap][elem] = temp;
            }
            for(elem = 0; elem < train_data->num_output; elem++)
            {
                temp = train_data->output[dat][elem];
                train_data->output[dat][elem] = train_data->output[swap][elem];
                train_data->output[swap][elem] = temp;
            }
        }
    }
}

/*
 * INTERNAL FUNCTION calculates min and max of train data
 */
void fann_get_min_max_data(fann_type ** data, unsigned int num_data, unsigned int num_elem, fann_type *min, fann_type *max)
{
    fann_type temp;
    unsigned int dat, elem;
    *min = *max = data[0][0];

    for(dat = 0; dat < num_data; dat++)
    {
        for(elem = 0; elem < num_elem; elem++)
        {
            temp = data[dat][elem];
            if(temp < *min)
                *min = temp;
            else if(temp > *max)
                *max = temp;
        }
    }
}


FANN_EXTERNAL fann_type FANN_API fann_get_min_train_input(struct fann_train_data *train_data)
{
    fann_type min, max;
    fann_get_min_max_data(train_data->input, train_data->num_data, train_data->num_input, &min, &max);
    return min;
}

FANN_EXTERNAL fann_type FANN_API fann_get_max_train_input(struct fann_train_data *train_data)
{
    fann_type min, max;
    fann_get_min_max_data(train_data->input, train_data->num_data, train_data->num_input, &min, &max);
    return max;
}

FANN_EXTERNAL fann_type FANN_API fann_get_min_train_output(struct fann_train_data *train_data)
{
    fann_type min, max;
    fann_get_min_max_data(train_data->output, train_data->num_data, train_data->num_output, &min, &max);
    return min;
}

FANN_EXTERNAL fann_type FANN_API fann_get_max_train_output(struct fann_train_data *train_data)
{
    fann_type min, max;
    fann_get_min_max_data(train_data->output, train_data->num_data, train_data->num_output, &min, &max);
    return max;
}

/*
 * INTERNAL FUNCTION Scales data to a specific range 
 */
void fann_scale_data(fann_type ** data, unsigned int num_data, unsigned int num_elem,
                     fann_type new_min, fann_type new_max)
{
    fann_type old_min, old_max;
    fann_get_min_max_data(data, num_data, num_elem, &old_min, &old_max);
    fann_scale_data_to_range(data, num_data, num_elem, old_min, old_max, new_min, new_max);
}

/*
 * INTERNAL FUNCTION Scales data to a specific range 
 */
FANN_EXTERNAL void FANN_API fann_scale_data_to_range(fann_type ** data, unsigned int num_data, unsigned int num_elem,
                     fann_type old_min, fann_type old_max, fann_type new_min, fann_type new_max)
{
    unsigned int dat, elem;
    fann_type temp, old_span, new_span, factor;

    old_span = old_max - old_min;
    new_span = new_max - new_min;
    factor = new_span / old_span;
    /*printf("max %f, min %f, factor %f\n", old_max, old_min, factor);*/

    for(dat = 0; dat < num_data; dat++)
    {
        for(elem = 0; elem < num_elem; elem++)
        {
            temp = (data[dat][elem] - old_min) * factor + new_min;
            if(temp < new_min)
            {
                data[dat][elem] = new_min;
                /*
                 * printf("error %f < %f\n", temp, new_min); 
                 */
            }
            else if(temp > new_max)
            {
                data[dat][elem] = new_max;
                /*
                 * printf("error %f > %f\n", temp, new_max); 
                 */
            }
            else
            {
                data[dat][elem] = temp;
            }
        }
    }
}


/*
 * Scales the inputs in the training data to the specified range 
 */
FANN_EXTERNAL void FANN_API fann_scale_input_train_data(struct fann_train_data *train_data,
                                                        fann_type new_min, fann_type new_max)
{
    fann_scale_data(train_data->input, train_data->num_data, train_data->num_input, new_min,
                    new_max);
}

/*
 * Scales the inputs in the training data to the specified range 
 */
FANN_EXTERNAL void FANN_API fann_scale_output_train_data(struct fann_train_data *train_data,
                                                         fann_type new_min, fann_type new_max)
{
    fann_scale_data(train_data->output, train_data->num_data, train_data->num_output, new_min,
                    new_max);
}

/*
 * Scales the inputs in the training data to the specified range 
 */
FANN_EXTERNAL void FANN_API fann_scale_train_data(struct fann_train_data *train_data,
                                                  fann_type new_min, fann_type new_max)
{
    fann_scale_data(train_data->input, train_data->num_data, train_data->num_input, new_min,
                    new_max);
    fann_scale_data(train_data->output, train_data->num_data, train_data->num_output, new_min,
                    new_max);
}

/*
 * merges training data into a single struct. 
 */
FANN_EXTERNAL struct fann_train_data *FANN_API fann_merge_train_data(struct fann_train_data *data1,
                                                                     struct fann_train_data *data2)
{
    unsigned int i;
    fann_type *data_input, *data_output;
    struct fann_train_data *dest = (struct fann_train_data *) malloc(sizeof(struct fann_train_data));

    if(dest == NULL)
    {
        // fann_error((struct fann_error*)data1, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_merge_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        return NULL;
    }

    if((data1->num_input != data2->num_input) || (data1->num_output != data2->num_output))
    {
        // fann_error((struct fann_error*)data1, FANN_E_TRAIN_DATA_MISMATCH);
        printf("Error: fann_merge_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        return NULL;
    }

    // fann_init_error_data((struct fann_error *) dest);
    // dest->error_log = data1->error_log;

    dest->num_data = data1->num_data+data2->num_data;
    dest->num_input = data1->num_input;
    dest->num_output = data1->num_output;
    dest->input = (fann_type **) calloc(dest->num_data, sizeof(fann_type *));
    if(dest->input == NULL)
    {
        // fann_error((struct fann_error*)data1, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_merge_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(dest);
        return NULL;
    }

    dest->output = (fann_type **) calloc(dest->num_data, sizeof(fann_type *));
    if(dest->output == NULL)
    {
        // fann_error((struct fann_error*)data1, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_merge_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(dest);
        return NULL;
    }

    data_input = (fann_type *) calloc(dest->num_input * dest->num_data, sizeof(fann_type));
    if(data_input == NULL)
    {
        // fann_error((struct fann_error*)data1, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_merge_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(dest);
        return NULL;
    }
    memcpy(data_input, data1->input[0], dest->num_input * data1->num_data * sizeof(fann_type));
    memcpy(data_input + (dest->num_input*data1->num_data), 
        data2->input[0], dest->num_input * data2->num_data * sizeof(fann_type));

    data_output = (fann_type *) calloc(dest->num_output * dest->num_data, sizeof(fann_type));
    if(data_output == NULL)
    {
        // fann_error((struct fann_error*)data1, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_merge_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(dest);
        return NULL;
    }
    memcpy(data_output, data1->output[0], dest->num_output * data1->num_data * sizeof(fann_type));
    memcpy(data_output + (dest->num_output*data1->num_data), 
        data2->output[0], dest->num_output * data2->num_data * sizeof(fann_type));

    for(i = 0; i != dest->num_data; i++)
    {
        dest->input[i] = data_input;
        data_input += dest->num_input;
        dest->output[i] = data_output;
        data_output += dest->num_output;
    }
    return dest;
}

/*
 * return a copy of a fann_train_data struct 
 */
FANN_EXTERNAL struct fann_train_data *FANN_API fann_duplicate_train_data(struct fann_train_data
                                                                         *data)
{
    unsigned int i;
    fann_type *data_input, *data_output;
    struct fann_train_data *dest =
        (struct fann_train_data *) malloc(sizeof(struct fann_train_data));

    if(dest == NULL)
    {
        // fann_error((struct fann_error*)data, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_duplicate_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        return NULL;
    }

    // fann_init_error_data((struct fann_error *) dest);
    // dest->error_log = data->error_log;

    dest->num_data = data->num_data;
    dest->num_input = data->num_input;
    dest->num_output = data->num_output;
    dest->input = (fann_type **) calloc(dest->num_data, sizeof(fann_type *));
    if(dest->input == NULL)
    {
        // fann_error((struct fann_error*)data, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_duplicate_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(dest);
        return NULL;
    }

    dest->output = (fann_type **) calloc(dest->num_data, sizeof(fann_type *));
    if(dest->output == NULL)
    {
        // fann_error((struct fann_error*)data, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_duplicate_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(dest);
        return NULL;
    }

    data_input = (fann_type *) calloc(dest->num_input * dest->num_data, sizeof(fann_type));
    if(data_input == NULL)
    {
        // fann_error((struct fann_error*)data, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_duplicate_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(dest);
        return NULL;
    }
    memcpy(data_input, data->input[0], dest->num_input * dest->num_data * sizeof(fann_type));

    data_output = (fann_type *) calloc(dest->num_output * dest->num_data, sizeof(fann_type));
    if(data_output == NULL)
    {
        // fann_error((struct fann_error*)data, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_duplicate_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(dest);
        return NULL;
    }
    memcpy(data_output, data->output[0], dest->num_output * dest->num_data * sizeof(fann_type));

    for(i = 0; i != dest->num_data; i++)
    {
        dest->input[i] = data_input;
        data_input += dest->num_input;
        dest->output[i] = data_output;
        data_output += dest->num_output;
    }
    return dest;
}

FANN_EXTERNAL struct fann_train_data *FANN_API fann_subset_train_data(struct fann_train_data
                                                                         *data, unsigned int pos,
                                                                         unsigned int length)
{
    unsigned int i;
    fann_type *data_input, *data_output;
    struct fann_train_data *dest =
        (struct fann_train_data *) malloc(sizeof(struct fann_train_data));

    if(dest == NULL)
    {
        // fann_error((struct fann_error*)data, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_subset_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        return NULL;
    }
    
    if(pos > data->num_data || pos+length > data->num_data)
    {
        // fann_error((struct fann_error*)data, FANN_E_TRAIN_DATA_SUBSET, pos, length, data->num_data);
        printf("Error: fann_subset_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        return NULL;
    }

    // fann_init_error_data((struct fann_error *) dest);
    // dest->error_log = data->error_log;

    dest->num_data = length;
    dest->num_input = data->num_input;
    dest->num_output = data->num_output;
    dest->input = (fann_type **) calloc(dest->num_data, sizeof(fann_type *));
    if(dest->input == NULL)
    {
        // fann_error((struct fann_error*)data, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_subset_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(dest);
        return NULL;
    }

    dest->output = (fann_type **) calloc(dest->num_data, sizeof(fann_type *));
    if(dest->output == NULL)
    {
        // fann_error((struct fann_error*)data, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_subset_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(dest);
        return NULL;
    }

    data_input = (fann_type *) calloc(dest->num_input * dest->num_data, sizeof(fann_type));
    if(data_input == NULL)
    {
        // fann_error((struct fann_error*)data, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_subset_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(dest);
        return NULL;
    }
    memcpy(data_input, data->input[pos], dest->num_input * dest->num_data * sizeof(fann_type));

    data_output = (fann_type *) calloc(dest->num_output * dest->num_data, sizeof(fann_type));
    if(data_output == NULL)
    {
        // fann_error((struct fann_error*)data, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_subset_train_data(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(dest);
        return NULL;
    }
    memcpy(data_output, data->output[pos], dest->num_output * dest->num_data * sizeof(fann_type));

    for(i = 0; i != dest->num_data; i++)
    {
        dest->input[i] = data_input;
        data_input += dest->num_input;
        dest->output[i] = data_output;
        data_output += dest->num_output;
    }
    return dest;
}

FANN_EXTERNAL unsigned int FANN_API fann_length_train_data(struct fann_train_data *data)
{
    return data->num_data;
}

FANN_EXTERNAL unsigned int FANN_API fann_num_input_train_data(struct fann_train_data *data)
{
    return data->num_input;
}

FANN_EXTERNAL unsigned int FANN_API fann_num_output_train_data(struct fann_train_data *data)
{
    return data->num_output;
}



/*
 * Creates an empty set of training data
 */
FANN_EXTERNAL struct fann_train_data * FANN_API fann_create_train(unsigned int num_data, unsigned int num_input, unsigned int num_output)
{
    fann_type *data_input, *data_output;
    unsigned int i;
    struct fann_train_data *data =
        (struct fann_train_data *) malloc(sizeof(struct fann_train_data));

    if(data == NULL)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_create_train(): FANN_E_CANT_ALLOCATE_MEM\n");
        return NULL;
    }
    
    // fann_init_error_data((struct fann_error *) data);

    data->num_data = num_data;
    data->num_input = num_input;
    data->num_output = num_output;
    data->input = (fann_type **) calloc(num_data, sizeof(fann_type *));
    if(data->input == NULL)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_create_train(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(data);
        return NULL;
    }

    data->output = (fann_type **) calloc(num_data, sizeof(fann_type *));
    if(data->output == NULL)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_create_train(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(data);
        return NULL;
    }

    data_input = (fann_type *) calloc(num_input * num_data, sizeof(fann_type));
    if(data_input == NULL)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_create_train(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(data);
        return NULL;
    }

    data_output = (fann_type *) calloc(num_output * num_data, sizeof(fann_type));
    if(data_output == NULL)
    {
        // fann_error(NULL, FANN_E_CANT_ALLOCATE_MEM);
        printf("Error: fann_create_train(): FANN_E_CANT_ALLOCATE_MEM\n");
        fann_destroy_train(data);
        return NULL;
    }

    for(i = 0; i != num_data; i++)
    {
        data->input[i] = data_input;
        data_input += num_input;
        data->output[i] = data_output;
        data_output += num_output;
    }
    return data;
}

FANN_EXTERNAL struct fann_train_data * FANN_API fann_create_train_pointer_array(unsigned int num_data, unsigned int num_input, fann_type **input, unsigned int num_output, fann_type **output)
{
    unsigned int i;
    struct fann_train_data *data;
    data = fann_create_train(num_data, num_input, num_output);

    if(data == NULL)
        return NULL;

    for (i = 0; i < num_data; ++i)
    {
        memcpy(data->input[i], input[i], num_input*sizeof(fann_type));
        memcpy(data->output[i], output[i], num_output*sizeof(fann_type));
    }
    
    return data;
}

FANN_EXTERNAL struct fann_train_data * FANN_API fann_create_train_array(unsigned int num_data, unsigned int num_input, fann_type *input, unsigned int num_output, fann_type *output)
{
    unsigned int i;
    struct fann_train_data *data;
    data = fann_create_train(num_data, num_input, num_output);

    if(data == NULL)
        return NULL;

    for (i = 0; i < num_data; ++i)
    {
        memcpy(data->input[i], &input[i*num_input], num_input*sizeof(fann_type));
        memcpy(data->output[i], &output[i*num_output], num_output*sizeof(fann_type));
    }
    
    return data;
}


/*
 * Creates training data from a callback function.
 */
FANN_EXTERNAL struct fann_train_data * FANN_API fann_create_train_from_callback(unsigned int num_data,
                                          unsigned int num_input,
                                          unsigned int num_output,
                                          void (FANN_API *user_function)( unsigned int,
                                                                 unsigned int,
                                                                 unsigned int,
                                                                 fann_type * ,
                                                                 fann_type * ))
{
    unsigned int i;
    struct fann_train_data *data = fann_create_train(num_data, num_input, num_output);
    if(data == NULL)
    {
        return NULL;
    }

    for( i = 0; i != num_data; i++)
    {
        (*user_function)(i, num_input, num_output, data->input[i], data->output[i]);
    }

    return data;
} 

FANN_EXTERNAL fann_type * FANN_API fann_get_train_input(struct fann_train_data * data, unsigned int position)
{
    if(position >= data->num_data)
        return NULL;
    return data->input[position];
}

FANN_EXTERNAL fann_type * FANN_API fann_get_train_output(struct fann_train_data * data, unsigned int position)
{
    if(position >= data->num_data)
        return NULL;
    return data->output[position];
}



/*
 * INTERNAL FUNCTION returns 0 if the desired error is reached and -1 if it is not reached
 */
int fann_desired_error_reached(struct fann *ann, float desired_error)
{
    switch (ann->train_stop_function)
    {
    case FANN_STOPFUNC_MSE:
        if(fann_get_MSE(ann) <= desired_error)
            return 0;
        break;
    case FANN_STOPFUNC_BIT:
        if(ann->num_bit_fail <= (unsigned int)desired_error)
            return 0;
        break;
    }
    return -1;
}

#ifndef FIXEDFANN
/*
 * Scale data in input vector before feed it to ann based on previously calculated parameters.
 */
FANN_EXTERNAL void FANN_API fann_scale_input( struct fann *ann, fann_type *input_vector )
{
    unsigned cur_neuron;
    if(ann->scale_mean_in == NULL)
    {
        // fann_error( (struct fann_error *) ann, FANN_E_SCALE_NOT_PRESENT );
        printf("Error: fann_scale_input(): FANN_E_SCALE_NOT_PRESENT\n");
        return;
    }
    
    for( cur_neuron = 0; cur_neuron < ann->num_input; cur_neuron++ )
                if(ann->scale_deviation_in[ cur_neuron ] != 0.0)
                        input_vector[ cur_neuron ] =
                                (
                                        ( input_vector[ cur_neuron ] - ann->scale_mean_in[ cur_neuron ] )
                                        / ann->scale_deviation_in[ cur_neuron ]
                                        - ( (fann_type)-1.0 ) /* This is old_min */
                                )
                                * ann->scale_factor_in[ cur_neuron ]
                                + ann->scale_new_min_in[ cur_neuron ];
}

/*
 * Scale data in output vector before feed it to ann based on previously calculated parameters.
 */
FANN_EXTERNAL void FANN_API fann_scale_output( struct fann *ann, fann_type *output_vector )
{
    unsigned cur_neuron;
    if(ann->scale_mean_in == NULL)
    {
        // fann_error( (struct fann_error *) ann, FANN_E_SCALE_NOT_PRESENT );
        printf("Error: fann_scale_output(): FANN_E_SCALE_NOT_PRESENT\n");
        return;
    }

    for( cur_neuron = 0; cur_neuron < ann->num_output; cur_neuron++ )
                if(ann->scale_deviation_out[ cur_neuron ] != 0.0)
                        output_vector[ cur_neuron ] =
                                (
                                        ( output_vector[ cur_neuron ] - ann->scale_mean_out[ cur_neuron ] )
                                        / ann->scale_deviation_out[ cur_neuron ]
                                        - ( (fann_type)-1.0 ) /* This is old_min */
                                )
                                * ann->scale_factor_out[ cur_neuron ]
                                + ann->scale_new_min_out[ cur_neuron ];
}

/*
 * Descale data in input vector after based on previously calculated parameters.
 */
FANN_EXTERNAL void FANN_API fann_descale_input( struct fann *ann, fann_type *input_vector )
{
    unsigned cur_neuron;
    if(ann->scale_mean_in == NULL)
    {
        // fann_error( (struct fann_error *) ann, FANN_E_SCALE_NOT_PRESENT );
        printf("Error: fann_descale_input(): FANN_E_SCALE_NOT_PRESENT\n");
        return;
    }

    for( cur_neuron = 0; cur_neuron < ann->num_input; cur_neuron++ )
                if(ann->scale_deviation_in[ cur_neuron ] != 0.0)
                        input_vector[ cur_neuron ] =
                                (
                                        (
                                                input_vector[ cur_neuron ]
                                                - ann->scale_new_min_in[ cur_neuron ]
                                        )
                                        / ann->scale_factor_in[ cur_neuron ]
                                        + ( (fann_type)-1.0 ) /* This is old_min */
                                )
                                * ann->scale_deviation_in[ cur_neuron ]
                                + ann->scale_mean_in[ cur_neuron ];
}

/*
 * Descale data in output vector after get it from ann based on previously calculated parameters.
 */
FANN_EXTERNAL void FANN_API fann_descale_output( struct fann *ann, fann_type *output_vector )
{
    unsigned cur_neuron;
    if(ann->scale_mean_in == NULL)
    {
        // fann_error( (struct fann_error *) ann, FANN_E_SCALE_NOT_PRESENT );
        printf("Error: fann_descale_output(): FANN_E_SCALE_NOT_PRESENT\n");
        return;
    }

    for( cur_neuron = 0; cur_neuron < ann->num_output; cur_neuron++ )
                if(ann->scale_deviation_out[ cur_neuron ] != 0.0)
                        output_vector[ cur_neuron ] =
                                (
                                        (
                                                output_vector[ cur_neuron ]
                                                - ann->scale_new_min_out[ cur_neuron ]
                                        )
                                        / ann->scale_factor_out[ cur_neuron ]
                                        + ( (fann_type)-1.0 ) /* This is old_min */
                                )
                                * ann->scale_deviation_out[ cur_neuron ]
                                + ann->scale_mean_out[ cur_neuron ];
}

/*
 * Scale input and output data based on previously calculated parameters.
 */
FANN_EXTERNAL void FANN_API fann_scale_train( struct fann *ann, struct fann_train_data *data )
{
    unsigned cur_sample;
    if(ann->scale_mean_in == NULL)
    {
        // fann_error( (struct fann_error *) ann, FANN_E_SCALE_NOT_PRESENT );
        printf("Error: fann_scale_train(): FANN_E_SCALE_NOT_PRESENT\n");
        return;
    }
    /* Check that we have good training data. */
    if(fann_check_input_output_sizes(ann, data) == -1)
        return;

    for( cur_sample = 0; cur_sample < data->num_data; cur_sample++ )
    {
        fann_scale_input( ann, data->input[ cur_sample ] );
        fann_scale_output( ann, data->output[ cur_sample ] );
    }
}

/*
 * Scale input and output data based on previously calculated parameters.
 */
FANN_EXTERNAL void FANN_API fann_descale_train( struct fann *ann, struct fann_train_data *data )
{
    unsigned cur_sample;
    if(ann->scale_mean_in == NULL)
    {
        // fann_error( (struct fann_error *) ann, FANN_E_SCALE_NOT_PRESENT );
        printf("Error: fann_descale_train(): FANN_E_SCALE_NOT_PRESENT\n");
        return;
    }
    /* Check that we have good training data. */
    if(fann_check_input_output_sizes(ann, data) == -1)
        return;

    for( cur_sample = 0; cur_sample < data->num_data; cur_sample++ )
    {
        fann_descale_input( ann, data->input[ cur_sample ] );
        fann_descale_output( ann, data->output[ cur_sample ] );
    }
}

#define SCALE_RESET( what, where, default_value )                           \
    for( cur_neuron = 0; cur_neuron < ann->num_##where##put; cur_neuron++ ) \
        ann->what##_##where[ cur_neuron ] = ( default_value );

#define SCALE_SET_PARAM( where )                                                                        \
    /* Calculate mean: sum(x)/length */                                                                 \
    for( cur_neuron = 0; cur_neuron < ann->num_##where##put; cur_neuron++ )                             \
        ann->scale_mean_##where[ cur_neuron ] = 0.0f;                                                   \
    for( cur_neuron = 0; cur_neuron < ann->num_##where##put; cur_neuron++ )                             \
        for( cur_sample = 0; cur_sample < data->num_data; cur_sample++ )                                \
            ann->scale_mean_##where[ cur_neuron ] += (float)data->where##put[ cur_sample ][ cur_neuron ];\
    for( cur_neuron = 0; cur_neuron < ann->num_##where##put; cur_neuron++ )                             \
        ann->scale_mean_##where[ cur_neuron ] /= (float)data->num_data;                                 \
    /* Calculate deviation: sqrt(sum((x-mean)^2)/length) */                                             \
    for( cur_neuron = 0; cur_neuron < ann->num_##where##put; cur_neuron++ )                             \
        ann->scale_deviation_##where[ cur_neuron ] = 0.0f;                                              \
    for( cur_neuron = 0; cur_neuron < ann->num_##where##put; cur_neuron++ )                             \
        for( cur_sample = 0; cur_sample < data->num_data; cur_sample++ )                                \
            ann->scale_deviation_##where[ cur_neuron ] +=                                               \
                /* Another local variable in macro? Oh no! */                                           \
                (                                                                                       \
                    (float)data->where##put[ cur_sample ][ cur_neuron ]                                 \
                    - ann->scale_mean_##where[ cur_neuron ]                                             \
                )                                                                                       \
                *                                                                                       \
                (                                                                                       \
                    (float)data->where##put[ cur_sample ][ cur_neuron ]                                 \
                    - ann->scale_mean_##where[ cur_neuron ]                                             \
                );                                                                                      \
    for( cur_neuron = 0; cur_neuron < ann->num_##where##put; cur_neuron++ )                             \
        ann->scale_deviation_##where[ cur_neuron ] =                                                    \
            sqrtf( ann->scale_deviation_##where[ cur_neuron ] / (float)data->num_data );            \
    /* Calculate factor: (new_max-new_min)/(old_max(1)-old_min(-1)) */                                  \
    /* Looks like we dont need whole array of factors? */                                               \
    for( cur_neuron = 0; cur_neuron < ann->num_##where##put; cur_neuron++ )                             \
        ann->scale_factor_##where[ cur_neuron ] =                                                       \
            ( new_##where##put_max - new_##where##put_min )                                             \
            /                                                                                           \
            ( 1.0f - ( -1.0f ) );                                                                       \
    /* Copy new minimum. */                                                                             \
    /* Looks like we dont need whole array of new minimums? */                                          \
    for( cur_neuron = 0; cur_neuron < ann->num_##where##put; cur_neuron++ )                             \
        ann->scale_new_min_##where[ cur_neuron ] = new_##where##put_min;

FANN_EXTERNAL int FANN_API fann_set_input_scaling_params(
    struct fann *ann,
    const struct fann_train_data *data,
    float new_input_min,
    float new_input_max)
{
    unsigned cur_neuron, cur_sample;

    /* Check that we have good training data. */
    /* No need for if( !params || !ann ) */
    if(data->num_input != ann->num_input
       || data->num_output != ann->num_output)
    {
        // fann_error( (struct fann_error *) ann, FANN_E_TRAIN_DATA_MISMATCH );
        printf("Error: fann_set_input_scaling_params(): FANN_E_TRAIN_DATA_MISMATCH\n");
        return -1;
    }

    if(ann->scale_mean_in == NULL)
        fann_allocate_scale(ann);
    
    if(ann->scale_mean_in == NULL)
        return -1;
        
    if( !data->num_data )
    {
        SCALE_RESET( scale_mean,        in, 0.0 )
        SCALE_RESET( scale_deviation,   in, 1.0 )
        SCALE_RESET( scale_new_min,     in, -1.0 )
        SCALE_RESET( scale_factor,      in, 1.0 )
    }
    else
    {
        SCALE_SET_PARAM( in );
    }

    return 0;
}

FANN_EXTERNAL int FANN_API fann_set_output_scaling_params(
    struct fann *ann,
    const struct fann_train_data *data,
    float new_output_min,
    float new_output_max)
{
    unsigned cur_neuron, cur_sample;

    /* Check that we have good training data. */
    /* No need for if( !params || !ann ) */
    if(data->num_input != ann->num_input
       || data->num_output != ann->num_output)
    {
        // fann_error( (struct fann_error *) ann, FANN_E_TRAIN_DATA_MISMATCH );
        printf("Error: fann_set_output_scaling_params(): FANN_E_TRAIN_DATA_MISMATCH\n");
        return -1;
    }

    if(ann->scale_mean_out == NULL)
        fann_allocate_scale(ann);
    
    if(ann->scale_mean_out == NULL)
        return -1;
        
    if( !data->num_data )
    {
        SCALE_RESET( scale_mean,        out,    0.0 )
        SCALE_RESET( scale_deviation,   out,    1.0 )
        SCALE_RESET( scale_new_min,     out,    -1.0 )
        SCALE_RESET( scale_factor,      out,    1.0 )
    }
    else
    {
        SCALE_SET_PARAM( out );
    }

    return 0;
}

/*
 * Calculate scaling parameters for future use based on training data.
 */
FANN_EXTERNAL int FANN_API fann_set_scaling_params(
    struct fann *ann,
    const struct fann_train_data *data,
    float new_input_min,
    float new_input_max,
    float new_output_min,
    float new_output_max)
{
    if(fann_set_input_scaling_params(ann, data, new_input_min, new_input_max) == 0)
        return fann_set_output_scaling_params(ann, data, new_output_min, new_output_max);
    else
        return -1;
}

/*
 * Clears scaling parameters.
 */
FANN_EXTERNAL int FANN_API fann_clear_scaling_params(struct fann *ann)
{
    unsigned cur_neuron;

    if(ann->scale_mean_out == NULL)
        fann_allocate_scale(ann);
    
    if(ann->scale_mean_out == NULL)
        return -1;
    
    SCALE_RESET( scale_mean,        in, 0.0 )
    SCALE_RESET( scale_deviation,   in, 1.0 )
    SCALE_RESET( scale_new_min,     in, -1.0 )
    SCALE_RESET( scale_factor,      in, 1.0 )

    SCALE_RESET( scale_mean,        out,    0.0 )
    SCALE_RESET( scale_deviation,   out,    1.0 )
    SCALE_RESET( scale_new_min,     out,    -1.0 )
    SCALE_RESET( scale_factor,      out,    1.0 )
    
    return 0;
}

#endif

int fann_check_input_output_sizes(struct fann *ann, struct fann_train_data *data)
{
    if(ann->num_input != data->num_input)
    {
        // fann_error((struct fann_error *) ann, FANN_E_INPUT_NO_MATCH, ann->num_input, data->num_input);
        printf("Error: fann_check_input_output_sizes(): FANN_E_INPUT_NO_MATCH\n");
        return -1;
    }
        
    if(ann->num_output != data->num_output)
    {
        // fann_error((struct fann_error *) ann, FANN_E_OUTPUT_NO_MATCH, ann->num_output, data->num_output);
        printf("Error: fann_check_input_output_sizes(): FANN_E_OUTPUT_NO_MATCH\n");
        return -1;
    }
    
    return 0;
}



///////////////////////////
//// From fann_train.c ////
///////////////////////////////////////////////////////////////////////////////////
#ifndef FIXEDFANN
/* INTERNAL FUNCTION
  Calculates the derived of a value, given an activation function
   and a steepness
*/
fann_type fann_activation_derived(unsigned int activation_function,
                                  fann_type steepness, fann_type value, fann_type sum)
{
    switch (activation_function)
    {
        case FANN_LINEAR:
        case FANN_LINEAR_PIECE:
        case FANN_LINEAR_PIECE_SYMMETRIC:
            return (fann_type) fann_linear_derive(steepness, value);
        case FANN_SIGMOID:
        case FANN_SIGMOID_STEPWISE:
            value = fann_clip(value, 0.01f, 0.99f);
            return (fann_type) fann_sigmoid_derive(steepness, value);
        case FANN_SIGMOID_SYMMETRIC:
        case FANN_SIGMOID_SYMMETRIC_STEPWISE:
            value = fann_clip(value, -0.98f, 0.98f);
            return (fann_type) fann_sigmoid_symmetric_derive(steepness, value);
        case FANN_GAUSSIAN:
            /* value = fann_clip(value, 0.01f, 0.99f); */
            return (fann_type) fann_gaussian_derive(steepness, value, sum);
        case FANN_GAUSSIAN_SYMMETRIC:
            /* value = fann_clip(value, -0.98f, 0.98f); */
            return (fann_type) fann_gaussian_symmetric_derive(steepness, value, sum);
        case FANN_ELLIOT:
            value = fann_clip(value, 0.01f, 0.99f);
            return (fann_type) fann_elliot_derive(steepness, value, sum);
        case FANN_ELLIOT_SYMMETRIC:
            value = fann_clip(value, -0.98f, 0.98f);
            return (fann_type) fann_elliot_symmetric_derive(steepness, value, sum);
        case FANN_SIN_SYMMETRIC:
            return (fann_type) fann_sin_symmetric_derive(steepness, sum);
        case FANN_COS_SYMMETRIC:
            return (fann_type) fann_cos_symmetric_derive(steepness, sum);
        case FANN_SIN:
            return (fann_type) fann_sin_derive(steepness, sum);
        case FANN_COS:
            return (fann_type) fann_cos_derive(steepness, sum);
        case FANN_THRESHOLD:
            // fann_error(NULL, FANN_E_CANT_TRAIN_ACTIVATION);
            printf("Error: fann_activation_derived(): FANN_E_CANT_TRAIN_ACTIVATION\n");
    }
    return 0;
}

/* INTERNAL FUNCTION
  Calculates the activation of a value, given an activation function
   and a steepness
*/
fann_type fann_activation(struct fann * ann, unsigned int activation_function, fann_type steepness,
                          fann_type value)
{
    value = fann_mult(steepness, value);
    fann_activation_switch(activation_function, value, value);
    return value;
}

/* Trains the network with the backpropagation algorithm.
 */
FANN_EXTERNAL void FANN_API fann_train(struct fann *ann, fann_type * input,
                                       fann_type * desired_output)
{
    fann_run(ann, input);

    fann_compute_MSE(ann, desired_output);

    fann_backpropagate_MSE(ann);

    fann_update_weights(ann);
}
#endif


/* INTERNAL FUNCTION
   Helper function to update the MSE value and return a diff which takes symmetric functions into account
*/
fann_type fann_update_MSE(struct fann *ann, struct fann_neuron* neuron, fann_type neuron_diff)
{
    float neuron_diff2;
    
    switch (neuron->activation_function)
    {
        case FANN_LINEAR_PIECE_SYMMETRIC:
        case FANN_THRESHOLD_SYMMETRIC:
        case FANN_SIGMOID_SYMMETRIC:
        case FANN_SIGMOID_SYMMETRIC_STEPWISE:
        case FANN_ELLIOT_SYMMETRIC:
        case FANN_GAUSSIAN_SYMMETRIC:
        case FANN_SIN_SYMMETRIC:
        case FANN_COS_SYMMETRIC:
            neuron_diff /= (fann_type)2.0;
            break;
        case FANN_THRESHOLD:
        case FANN_LINEAR:
        case FANN_SIGMOID:
        case FANN_SIGMOID_STEPWISE:
        case FANN_GAUSSIAN:
        case FANN_GAUSSIAN_STEPWISE:
        case FANN_ELLIOT:
        case FANN_LINEAR_PIECE:
        case FANN_SIN:
        case FANN_COS:
            break;
    }

#ifdef FIXEDFANN
        neuron_diff2 =
            (neuron_diff / (float) ann->multiplier) * (neuron_diff / (float) ann->multiplier);
#else
        neuron_diff2 = (float) (neuron_diff * neuron_diff);
#endif

    ann->MSE_value += neuron_diff2;

    /*printf("neuron_diff %f = (%f - %f)[/2], neuron_diff2=%f, sum=%f, MSE_value=%f, num_MSE=%d\n", neuron_diff, *desired_output, neuron_value, neuron_diff2, last_layer_begin->sum, ann->MSE_value, ann->num_MSE); */
    if(fann_abs(neuron_diff) >= ann->bit_fail_limit)
    {
        ann->num_bit_fail++;
    }
    
    return neuron_diff;
}

/* Tests the network.
 */
FANN_EXTERNAL fann_type *FANN_API fann_test(struct fann *ann, fann_type * input,
                                            fann_type * desired_output)
{
    fann_type neuron_value;
    fann_type *output_begin = fann_run(ann, input);
    fann_type *output_it;
    const fann_type *output_end = output_begin + ann->num_output;
    fann_type neuron_diff;
    struct fann_neuron *output_neuron = (ann->last_layer - 1)->first_neuron;

    /* calculate the error */
    for(output_it = output_begin; output_it != output_end; output_it++)
    {
        neuron_value = *output_it;

        neuron_diff = (*desired_output - neuron_value);

        neuron_diff = fann_update_MSE(ann, output_neuron, neuron_diff);
        
        desired_output++;
        output_neuron++;

        ann->num_MSE++;
    }

    return output_begin;
}

/* get the mean square error.
 */
FANN_EXTERNAL float FANN_API fann_get_MSE(struct fann *ann)
{
    if(ann->num_MSE)
    {
        return ann->MSE_value / (float) ann->num_MSE;
    }
    else
    {
        return 0;
    }
}

FANN_EXTERNAL unsigned int FANN_API fann_get_bit_fail(struct fann *ann)
{
    return ann->num_bit_fail;   
}

/* reset the mean square error.
 */
FANN_EXTERNAL void FANN_API fann_reset_MSE(struct fann *ann)
{
/*printf("resetMSE %d %f\n", ann->num_MSE, ann->MSE_value);*/
    ann->num_MSE = 0;
    ann->MSE_value = 0;
    ann->num_bit_fail = 0;
}

#ifndef FIXEDFANN

/* INTERNAL FUNCTION
    compute the error at the network output
    (usually, after forward propagation of a certain input vector, fann_run)
    the error is a sum of squares for all the output units
    also increments a counter because MSE is an average of such errors

    After this train_errors in the output layer will be set to:
    neuron_value_derived * (desired_output - neuron_value)
 */
void fann_compute_MSE(struct fann *ann, fann_type * desired_output)
{
    fann_type neuron_value, neuron_diff, *error_it = 0, *error_begin = 0;
    struct fann_neuron *last_layer_begin = (ann->last_layer - 1)->first_neuron;
    const struct fann_neuron *last_layer_end = last_layer_begin + ann->num_output;
    const struct fann_neuron *first_neuron = ann->first_layer->first_neuron;

    /* if no room allocated for the error variabels, allocate it now */
    if(ann->train_errors == NULL)
    {
        ann->train_errors = (fann_type *) calloc(ann->total_neurons, sizeof(fann_type));
        if(ann->train_errors == NULL)
        {
            // fann_error((struct fann_error *) ann, FANN_E_CANT_ALLOCATE_MEM);
            printf("Error: fann_compute_MSE(): FANN_E_CANT_ALLOCATE_MEM\n");
            return;
        }
    }
    else
    {
        /* clear the error variabels */
        memset(ann->train_errors, 0, (ann->total_neurons) * sizeof(fann_type));
    }
    error_begin = ann->train_errors;

#ifdef DEBUGTRAIN
    printf("\ncalculate errors\n");
#endif
    /* calculate the error and place it in the output layer */
    error_it = error_begin + (last_layer_begin - first_neuron);

    for(; last_layer_begin != last_layer_end; last_layer_begin++)
    {
        neuron_value = last_layer_begin->value;
        neuron_diff = *desired_output - neuron_value;

        neuron_diff = fann_update_MSE(ann, last_layer_begin, neuron_diff);

        if(ann->train_error_function)
        {                       /* TODO make switch when more functions */
            if(neuron_diff < -.9999999)
                neuron_diff = -17.0;
            else if(neuron_diff > .9999999)
                neuron_diff = 17.0;
            else
                neuron_diff = (fann_type) log((1.0 + neuron_diff) / (1.0 - neuron_diff));
        }

        *error_it = fann_activation_derived(last_layer_begin->activation_function,
                                            last_layer_begin->activation_steepness, neuron_value,
                                            last_layer_begin->sum) * neuron_diff;

        desired_output++;
        error_it++;

        ann->num_MSE++;
    }
}

/* INTERNAL FUNCTION
   Propagate the error backwards from the output layer.

   After this the train_errors in the hidden layers will be:
   neuron_value_derived * sum(outgoing_weights * connected_neuron)
*/
void fann_backpropagate_MSE(struct fann *ann)
{
    fann_type tmp_error;
    unsigned int i;
    struct fann_layer *layer_it;
    struct fann_neuron *neuron_it, *last_neuron;
    struct fann_neuron **connections;

    fann_type *error_begin = ann->train_errors;
    fann_type *error_prev_layer;
    fann_type *weights;
    const struct fann_neuron *first_neuron = ann->first_layer->first_neuron;
    const struct fann_layer *second_layer = ann->first_layer + 1;
    struct fann_layer *last_layer = ann->last_layer;

    /* go through all the layers, from last to first.
     * And propagate the error backwards */
    for(layer_it = last_layer - 1; layer_it > second_layer; --layer_it)
    {
        last_neuron = layer_it->last_neuron;

        /* for each connection in this layer, propagate the error backwards */
        if(ann->connection_rate >= 1)
        {
            if(ann->network_type == FANN_NETTYPE_LAYER)
            {
                error_prev_layer = error_begin + ((layer_it - 1)->first_neuron - first_neuron);
            }
            else
            {
                error_prev_layer = error_begin;
            }

            for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
            {

                tmp_error = error_begin[neuron_it - first_neuron];
                weights = ann->weights + neuron_it->first_con;
                for(i = neuron_it->last_con - neuron_it->first_con; i--;)
                {
                    /*printf("i = %d\n", i);
                     * printf("error_prev_layer[%d] = %f\n", i, error_prev_layer[i]);
                     * printf("weights[%d] = %f\n", i, weights[i]); */
                    error_prev_layer[i] += tmp_error * weights[i];
                }
            }
        }
        else
        {
            for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
            {

                tmp_error = error_begin[neuron_it - first_neuron];
                weights = ann->weights + neuron_it->first_con;
                connections = ann->connections + neuron_it->first_con;
                for(i = neuron_it->last_con - neuron_it->first_con; i--;)
                {
                    error_begin[connections[i] - first_neuron] += tmp_error * weights[i];
                }
            }
        }

        /* then calculate the actual errors in the previous layer */
        error_prev_layer = error_begin + ((layer_it - 1)->first_neuron - first_neuron);
        last_neuron = (layer_it - 1)->last_neuron;

        for(neuron_it = (layer_it - 1)->first_neuron; neuron_it != last_neuron; neuron_it++)
        {
            *error_prev_layer *= fann_activation_derived(neuron_it->activation_function, 
                neuron_it->activation_steepness, neuron_it->value, neuron_it->sum);
            error_prev_layer++;
        }
        
    }
}

/* INTERNAL FUNCTION
   Update weights for incremental training
*/
void fann_update_weights(struct fann *ann)
{
    struct fann_neuron *neuron_it, *last_neuron, *prev_neurons;
    fann_type tmp_error, delta_w, *weights;
    struct fann_layer *layer_it;
    unsigned int i;
    unsigned int num_connections;

    /* store some variabels local for fast access */
    const float learning_rate = ann->learning_rate;
    const float learning_momentum = ann->learning_momentum;        
    struct fann_neuron *first_neuron = ann->first_layer->first_neuron;
    struct fann_layer *first_layer = ann->first_layer;
    const struct fann_layer *last_layer = ann->last_layer;
    fann_type *error_begin = ann->train_errors;
    fann_type *deltas_begin, *weights_deltas;

    /* if no room allocated for the deltas, allocate it now */
    if(ann->prev_weights_deltas == NULL)
    {
        ann->prev_weights_deltas =
            (fann_type *) calloc(ann->total_connections_allocated, sizeof(fann_type));
        if(ann->prev_weights_deltas == NULL)
        {
            // fann_error((struct fann_error *) ann, FANN_E_CANT_ALLOCATE_MEM);
            printf("Error: fann_update_weights(): FANN_E_CANT_ALLOCATE_MEM\n");
            return;
        }       
    }

#ifdef DEBUGTRAIN
    printf("\nupdate weights\n");
#endif
    deltas_begin = ann->prev_weights_deltas;
    prev_neurons = first_neuron;
    for(layer_it = (first_layer + 1); layer_it != last_layer; layer_it++)
    {
#ifdef DEBUGTRAIN
        printf("layer[%d]\n", layer_it - first_layer);
#endif
        last_neuron = layer_it->last_neuron;
        if(ann->connection_rate >= 1)
        {
            if(ann->network_type == FANN_NETTYPE_LAYER)
            {
                prev_neurons = (layer_it - 1)->first_neuron;
            }
            for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
            {
                tmp_error = error_begin[neuron_it - first_neuron] * learning_rate;
                num_connections = neuron_it->last_con - neuron_it->first_con;
                weights = ann->weights + neuron_it->first_con;
                weights_deltas = deltas_begin + neuron_it->first_con;
                for(i = 0; i != num_connections; i++)
                {
                    delta_w = tmp_error * prev_neurons[i].value + learning_momentum * weights_deltas[i];
                    weights[i] += delta_w ;
                    weights_deltas[i] = delta_w;
                }
            }
        }
        else
        {
            for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
            {
                tmp_error = error_begin[neuron_it - first_neuron] * learning_rate;
                num_connections = neuron_it->last_con - neuron_it->first_con;
                weights = ann->weights + neuron_it->first_con;
                weights_deltas = deltas_begin + neuron_it->first_con;
                for(i = 0; i != num_connections; i++)
                {
                    delta_w = tmp_error * prev_neurons[i].value + learning_momentum * weights_deltas[i];
                    weights[i] += delta_w;
                    weights_deltas[i] = delta_w;
                }
            }
        }
    }
}

/* INTERNAL FUNCTION
   Update slopes for batch training
   layer_begin = ann->first_layer+1 and layer_end = ann->last_layer-1
   will update all slopes.

*/
void fann_update_slopes_batch(struct fann *ann, struct fann_layer *layer_begin,
                              struct fann_layer *layer_end)
{
    struct fann_neuron *neuron_it, *last_neuron, *prev_neurons, **connections;
    fann_type tmp_error;
    unsigned int i, num_connections;

    /* store some variabels local for fast access */
    struct fann_neuron *first_neuron = ann->first_layer->first_neuron;
    fann_type *error_begin = ann->train_errors;
    fann_type *slope_begin, *neuron_slope;

    /* if no room allocated for the slope variabels, allocate it now */
    if(ann->train_slopes == NULL)
    {
        ann->train_slopes =
            (fann_type *) calloc(ann->total_connections_allocated, sizeof(fann_type));
        if(ann->train_slopes == NULL)
        {
            // fann_error((struct fann_error *) ann, FANN_E_CANT_ALLOCATE_MEM);
            printf("Error: fann_update_slopes_batch(): FANN_E_CANT_ALLOCATE_MEM\n");
            return;
        }
    }

    if(layer_begin == NULL)
    {
        layer_begin = ann->first_layer + 1;
    }

    if(layer_end == NULL)
    {
        layer_end = ann->last_layer - 1;
    }

    slope_begin = ann->train_slopes;

#ifdef DEBUGTRAIN
    printf("\nupdate slopes\n");
#endif

    prev_neurons = first_neuron;

    for(; layer_begin <= layer_end; layer_begin++)
    {
#ifdef DEBUGTRAIN
        printf("layer[%d]\n", layer_begin - ann->first_layer);
#endif
        last_neuron = layer_begin->last_neuron;
        if(ann->connection_rate >= 1)
        {
            if(ann->network_type == FANN_NETTYPE_LAYER)
            {
                prev_neurons = (layer_begin - 1)->first_neuron;
            }

            for(neuron_it = layer_begin->first_neuron; neuron_it != last_neuron; neuron_it++)
            {
                tmp_error = error_begin[neuron_it - first_neuron];
                neuron_slope = slope_begin + neuron_it->first_con;
                num_connections = neuron_it->last_con - neuron_it->first_con;
                for(i = 0; i != num_connections; i++)
                {
                    neuron_slope[i] += tmp_error * prev_neurons[i].value;
                }
            }
        }
        else
        {
            for(neuron_it = layer_begin->first_neuron; neuron_it != last_neuron; neuron_it++)
            {
                tmp_error = error_begin[neuron_it - first_neuron];
                neuron_slope = slope_begin + neuron_it->first_con;
                num_connections = neuron_it->last_con - neuron_it->first_con;
                connections = ann->connections + neuron_it->first_con;
                for(i = 0; i != num_connections; i++)
                {
                    neuron_slope[i] += tmp_error * connections[i]->value;
                }
            }
        }
    }
}

/* INTERNAL FUNCTION
   Clears arrays used for training before a new training session.
   Also creates the arrays that do not exist yet.
 */
void fann_clear_train_arrays(struct fann *ann)
{
    unsigned int i;
    fann_type delta_zero;

    /* if no room allocated for the slope variabels, allocate it now
     * (calloc clears mem) */
    if(ann->train_slopes == NULL)
    {
        ann->train_slopes =
            (fann_type *) calloc(ann->total_connections_allocated, sizeof(fann_type));
        if(ann->train_slopes == NULL)
        {
            // fann_error((struct fann_error *) ann, FANN_E_CANT_ALLOCATE_MEM);
            printf("Error: fann_clear_train_arrays(): FANN_E_CANT_ALLOCATE_MEM\n");
            return;
        }
    }
    else
    {
        memset(ann->train_slopes, 0, (ann->total_connections_allocated) * sizeof(fann_type));
    }

    /* if no room allocated for the variabels, allocate it now */
    if(ann->prev_steps == NULL)
    {
        ann->prev_steps = (fann_type *) malloc(ann->total_connections_allocated * sizeof(fann_type));
        if(ann->prev_steps == NULL)
        {
            // fann_error((struct fann_error *) ann, FANN_E_CANT_ALLOCATE_MEM);
            printf("Error: fann_clear_train_arrays(): FANN_E_CANT_ALLOCATE_MEM\n");
            return;
        }
    }

    if(ann->training_algorithm == FANN_TRAIN_RPROP)
    {
        delta_zero = ann->rprop_delta_zero;
        
        for(i = 0; i < ann->total_connections_allocated; i++)
            ann->prev_steps[i] = delta_zero;
    }
    else
    {
        memset(ann->prev_steps, 0, (ann->total_connections_allocated) * sizeof(fann_type));
    }

    /* if no room allocated for the variabels, allocate it now */
    if(ann->prev_train_slopes == NULL)
    {
        ann->prev_train_slopes =
            (fann_type *) calloc(ann->total_connections_allocated, sizeof(fann_type));
        if(ann->prev_train_slopes == NULL)
        {
            // fann_error((struct fann_error *) ann, FANN_E_CANT_ALLOCATE_MEM);
            printf("Error: fann_clear_train_arrays(): FANN_E_CANT_ALLOCATE_MEM\n");
            return;
        }
    }
    else
    {
        memset(ann->prev_train_slopes, 0, (ann->total_connections_allocated) * sizeof(fann_type));
    }
}

/* INTERNAL FUNCTION
   Update weights for batch training
 */
void fann_update_weights_batch(struct fann *ann, unsigned int num_data, unsigned int first_weight,
                               unsigned int past_end)
{
    fann_type *train_slopes = ann->train_slopes;
    fann_type *weights = ann->weights;
    const float epsilon = ann->learning_rate / num_data;
    unsigned int i = first_weight;

    for(; i != past_end; i++)
    {
        weights[i] += train_slopes[i] * epsilon;
        train_slopes[i] = 0.0;
    }
}

/* INTERNAL FUNCTION
   The quickprop training algorithm
 */
void fann_update_weights_quickprop(struct fann *ann, unsigned int num_data,
                                   unsigned int first_weight, unsigned int past_end)
{
    fann_type *train_slopes = ann->train_slopes;
    fann_type *weights = ann->weights;
    fann_type *prev_steps = ann->prev_steps;
    fann_type *prev_train_slopes = ann->prev_train_slopes;

    fann_type w, prev_step, slope, prev_slope, next_step;

    float epsilon = ann->learning_rate / num_data;
    float decay = ann->quickprop_decay; /*-0.0001;*/
    float mu = ann->quickprop_mu;   /*1.75; */
    float shrink_factor = (float) (mu / (1.0 + mu));
    
    unsigned int i = first_weight;

    for(; i != past_end; i++)
    {
        w = weights[i];
        prev_step = prev_steps[i];
        slope = train_slopes[i] + decay * w;
        prev_slope = prev_train_slopes[i];
        next_step = 0.0;
        
        /* The step must always be in direction opposite to the slope. */
        if(prev_step > 0.001)
        {
            /* If last step was positive...  */
            if(slope > 0.0) /*  Add in linear term if current slope is still positive. */
                next_step += epsilon * slope;

            /*If current slope is close to or larger than prev slope...  */
            if(slope > (shrink_factor * prev_slope))
                next_step += mu * prev_step;    /* Take maximum size negative step. */
            else
                next_step += prev_step * slope / (prev_slope - slope);  /* Else, use quadratic estimate. */
        }
        else if(prev_step < -0.001)
        {
            /* If last step was negative...  */
            if(slope < 0.0) /*  Add in linear term if current slope is still negative. */
                next_step += epsilon * slope;

            /* If current slope is close to or more neg than prev slope... */
            if(slope < (shrink_factor * prev_slope))
                next_step += mu * prev_step;    /* Take maximum size negative step. */
            else
                next_step += prev_step * slope / (prev_slope - slope);  /* Else, use quadratic estimate. */
        }
        else /* Last step was zero, so use only linear term. */
            next_step += epsilon * slope; 

        /*
        if(next_step > 1000 || next_step < -1000)
        {
            printf("quickprop[%d] weight=%f, slope=%f, prev_slope=%f, next_step=%f, prev_step=%f\n",
                   i, weights[i], slope, prev_slope, next_step, prev_step);
            
               if(next_step > 1000)
               next_step = 1000;
               else
               next_step = -1000;
        }
        */

        /* update global data arrays */
        prev_steps[i] = next_step;

        w += next_step;

        if(w > 1500)
            weights[i] = 1500;
        else if(w < -1500)
            weights[i] = -1500;
        else
            weights[i] = w;

        /*weights[i] = w;*/

        prev_train_slopes[i] = slope;
        train_slopes[i] = 0.0;
    }
}

/* INTERNAL FUNCTION
   The iRprop- algorithm
*/
void fann_update_weights_irpropm(struct fann *ann, unsigned int first_weight, unsigned int past_end)
{
    fann_type *train_slopes = ann->train_slopes;
    fann_type *weights = ann->weights;
    fann_type *prev_steps = ann->prev_steps;
    fann_type *prev_train_slopes = ann->prev_train_slopes;

    fann_type prev_step, slope, prev_slope, next_step, same_sign;

    float increase_factor = ann->rprop_increase_factor; /*1.2; */
    float decrease_factor = ann->rprop_decrease_factor; /*0.5; */
    float delta_min = ann->rprop_delta_min; /*0.0; */
    float delta_max = ann->rprop_delta_max; /*50.0; */

    unsigned int i = first_weight;

    for(; i != past_end; i++)
    {
        prev_step = fann_max(prev_steps[i], (fann_type) 0.0001);    /* prev_step may not be zero because then the training will stop */
        slope = train_slopes[i];
        prev_slope = prev_train_slopes[i];

        same_sign = prev_slope * slope;

        if(same_sign >= 0.0)
            next_step = fann_min(prev_step * increase_factor, delta_max);
        else
        {
            next_step = fann_max(prev_step * decrease_factor, delta_min);
            slope = 0;
        }

        if(slope < 0)
        {
            weights[i] -= next_step;
            if(weights[i] < -1500)
                weights[i] = -1500;
        }
        else
        {
            weights[i] += next_step;
            if(weights[i] > 1500)
                weights[i] = 1500;
        }

        /*if(i == 2){
         * printf("weight=%f, slope=%f, next_step=%f, prev_step=%f\n", weights[i], slope, next_step, prev_step);
         * } */

        /* update global data arrays */
        prev_steps[i] = next_step;
        prev_train_slopes[i] = slope;
        train_slopes[i] = 0.0;
    }
}

/* INTERNAL FUNCTION
   The SARprop- algorithm
*/
void fann_update_weights_sarprop(struct fann *ann, unsigned int epoch, unsigned int first_weight, unsigned int past_end)
{
    fann_type *train_slopes = ann->train_slopes;
    fann_type *weights = ann->weights;
    fann_type *prev_steps = ann->prev_steps;
    fann_type *prev_train_slopes = ann->prev_train_slopes;

    fann_type prev_step, slope, prev_slope, next_step = 0, same_sign;

    /* These should be set from variables */
    float increase_factor = ann->rprop_increase_factor; /*1.2; */
    float decrease_factor = ann->rprop_decrease_factor; /*0.5; */
    /* TODO: why is delta_min 0.0 in iRprop? SARPROP uses 1x10^-6 (Braun and Riedmiller, 1993) */
    float delta_min = 0.000001f;
    float delta_max = ann->rprop_delta_max; /*50.0; */
    float weight_decay_shift = ann->sarprop_weight_decay_shift; /* ld 0.01 = -6.644 */
    float step_error_threshold_factor = ann->sarprop_step_error_threshold_factor; /* 0.1 */
    float step_error_shift = ann->sarprop_step_error_shift; /* ld 3 = 1.585 */
    float T = ann->sarprop_temperature;
    float MSE = fann_get_MSE(ann);
    float RMSE = sqrtf(MSE);

    unsigned int i = first_weight;


    /* for all weights; TODO: are biases included? */
    for(; i != past_end; i++)
    {
        /* TODO: confirm whether 1x10^-6 == delta_min is really better */
        prev_step = fann_max(prev_steps[i], (fann_type) 0.000001);  /* prev_step may not be zero because then the training will stop */
        /* calculate SARPROP slope; TODO: better as new error function? (see SARPROP paper)*/
        slope = -train_slopes[i] - weights[i] * (fann_type)fann_exp2(-T * epoch + weight_decay_shift);

        /* TODO: is prev_train_slopes[i] 0.0 in the beginning? */
        prev_slope = prev_train_slopes[i];

        same_sign = prev_slope * slope;

        if(same_sign > 0.0)
        {
            next_step = fann_min(prev_step * increase_factor, delta_max);
            /* TODO: are the signs inverted? see differences between SARPROP paper and iRprop */
            if (slope < 0.0)
                weights[i] += next_step;
            else
                weights[i] -= next_step;
        }
        else if(same_sign < 0.0)
        {
            if(prev_step < step_error_threshold_factor * MSE){
                next_step = prev_step * decrease_factor + fann_rand(0, 1) * RMSE * (fann_type)fann_exp2(-T * epoch + step_error_shift);
            }
            else
                next_step = fann_max(prev_step * decrease_factor, delta_min);

            slope = 0.0;
        }
        else
        {
            if(slope < 0.0)
                weights[i] += prev_step;
            else
                weights[i] -= prev_step;
        }


        /*if(i == 2){
         * printf("weight=%f, slope=%f, next_step=%f, prev_step=%f\n", weights[i], slope, next_step, prev_step);
         * } */

        /* update global data arrays */
        prev_steps[i] = next_step;
        prev_train_slopes[i] = slope;
        train_slopes[i] = 0.0;
    }
}

#endif

FANN_GET_SET(enum fann_train_enum, training_algorithm)
FANN_GET_SET(float, learning_rate)

FANN_EXTERNAL void FANN_API fann_set_activation_function_hidden(struct fann *ann, enum fann_activationfunc_enum activation_function)
{
    struct fann_neuron *last_neuron, *neuron_it;
    struct fann_layer *layer_it;
    struct fann_layer *last_layer = ann->last_layer - 1;    /* -1 to not update the output layer */

    for(layer_it = ann->first_layer + 1; layer_it != last_layer; layer_it++)
    {
        last_neuron = layer_it->last_neuron;
        for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
        {
            neuron_it->activation_function = activation_function;
        }
    }
}

FANN_EXTERNAL struct fann_layer* FANN_API fann_get_layer(struct fann *ann, int layer)
{
    if(layer <= 0 || layer >= (ann->last_layer - ann->first_layer))
    {
        // fann_error((struct fann_error *) ann, FANN_E_INDEX_OUT_OF_BOUND, layer);
        printf("Error: fann_get_layer(): FANN_E_INDEX_OUT_OF_BOUND\n");
        return NULL;
    }
    
    return ann->first_layer + layer;    
}

FANN_EXTERNAL struct fann_neuron* FANN_API fann_get_neuron_layer(struct fann *ann, struct fann_layer* layer, int neuron)
{
    if(neuron >= (layer->last_neuron - layer->first_neuron))
    {
        // fann_error((struct fann_error *) ann, FANN_E_INDEX_OUT_OF_BOUND, neuron);
        printf("Error: fann_get_neuron_layer(): FANN_E_INDEX_OUT_OF_BOUND\n");
        return NULL;    
    }
    
    return layer->first_neuron + neuron;
}

FANN_EXTERNAL struct fann_neuron* FANN_API fann_get_neuron(struct fann *ann, unsigned int layer, int neuron)
{
    struct fann_layer *layer_it = fann_get_layer(ann, layer);
    if(layer_it == NULL)
        return NULL;
    return fann_get_neuron_layer(ann, layer_it, neuron);
}

FANN_EXTERNAL enum fann_activationfunc_enum FANN_API fann_get_activation_function(struct fann *ann, int layer, int neuron)
{
    struct fann_neuron* neuron_it = fann_get_neuron(ann, layer, neuron);
    if (neuron_it == NULL)
    {
        return (enum fann_activationfunc_enum)-1; /* layer or neuron out of bounds */
    }
    else
    {
        return neuron_it->activation_function;
    }
}

FANN_EXTERNAL void FANN_API fann_set_activation_function(struct fann *ann,
                                                                enum fann_activationfunc_enum
                                                                activation_function,
                                                                int layer,
                                                                int neuron)
{
    struct fann_neuron* neuron_it = fann_get_neuron(ann, layer, neuron);
    if(neuron_it == NULL)
        return;

    neuron_it->activation_function = activation_function;
}

FANN_EXTERNAL void FANN_API fann_set_activation_function_layer(struct fann *ann,
                                                                enum fann_activationfunc_enum
                                                                activation_function,
                                                                int layer)
{
    struct fann_neuron *last_neuron, *neuron_it;
    struct fann_layer *layer_it = fann_get_layer(ann, layer);
    
    if(layer_it == NULL)
        return;

    last_neuron = layer_it->last_neuron;
    for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
    {
        neuron_it->activation_function = activation_function;
    }
}


FANN_EXTERNAL void FANN_API fann_set_activation_function_output(struct fann *ann,
                                                                enum fann_activationfunc_enum activation_function)
{
    struct fann_neuron *last_neuron, *neuron_it;
    struct fann_layer *last_layer = ann->last_layer - 1;

    last_neuron = last_layer->last_neuron;
    for(neuron_it = last_layer->first_neuron; neuron_it != last_neuron; neuron_it++)
    {
        neuron_it->activation_function = activation_function;
    }
}

FANN_EXTERNAL void FANN_API fann_set_activation_steepness_hidden(struct fann *ann,
                                                                 fann_type steepness)
{
    struct fann_neuron *last_neuron, *neuron_it;
    struct fann_layer *layer_it;
    struct fann_layer *last_layer = ann->last_layer - 1;    /* -1 to not update the output layer */

    for(layer_it = ann->first_layer + 1; layer_it != last_layer; layer_it++)
    {
        last_neuron = layer_it->last_neuron;
        for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
        {
            neuron_it->activation_steepness = steepness;
        }
    }
}

FANN_EXTERNAL fann_type FANN_API fann_get_activation_steepness(struct fann *ann, int layer, int neuron)
{
    struct fann_neuron* neuron_it = fann_get_neuron(ann, layer, neuron);
    if(neuron_it == NULL)
    {
        return -1; /* layer or neuron out of bounds */
    }
    else
    {
        return neuron_it->activation_steepness;
    }
}

FANN_EXTERNAL void FANN_API fann_set_activation_steepness(struct fann *ann,
                                                                fann_type steepness,
                                                                int layer,
                                                                int neuron)
{
    struct fann_neuron* neuron_it = fann_get_neuron(ann, layer, neuron);
    if(neuron_it == NULL)
        return;

    neuron_it->activation_steepness = steepness;
}

FANN_EXTERNAL void FANN_API fann_set_activation_steepness_layer(struct fann *ann,
                                                                fann_type steepness,
                                                                int layer)
{
    struct fann_neuron *last_neuron, *neuron_it;
    struct fann_layer *layer_it = fann_get_layer(ann, layer);
    
    if(layer_it == NULL)
        return;

    last_neuron = layer_it->last_neuron;
    for(neuron_it = layer_it->first_neuron; neuron_it != last_neuron; neuron_it++)
    {
        neuron_it->activation_steepness = steepness;
    }
}

FANN_EXTERNAL void FANN_API fann_set_activation_steepness_output(struct fann *ann,
                                                                 fann_type steepness)
{
    struct fann_neuron *last_neuron, *neuron_it;
    struct fann_layer *last_layer = ann->last_layer - 1;

    last_neuron = last_layer->last_neuron;
    for(neuron_it = last_layer->first_neuron; neuron_it != last_neuron; neuron_it++)
    {
        neuron_it->activation_steepness = steepness;
    }
}

FANN_GET_SET(enum fann_errorfunc_enum, train_error_function)
FANN_GET_SET(fann_callback_type, callback)
FANN_GET_SET(float, quickprop_decay)
FANN_GET_SET(float, quickprop_mu)
FANN_GET_SET(float, rprop_increase_factor)
FANN_GET_SET(float, rprop_decrease_factor)
FANN_GET_SET(float, rprop_delta_min)
FANN_GET_SET(float, rprop_delta_max)
FANN_GET_SET(float, rprop_delta_zero)
FANN_GET_SET(float, sarprop_weight_decay_shift)
FANN_GET_SET(float, sarprop_step_error_threshold_factor)
FANN_GET_SET(float, sarprop_step_error_shift)
FANN_GET_SET(float, sarprop_temperature)
FANN_GET_SET(enum fann_stopfunc_enum, train_stop_function)
FANN_GET_SET(fann_type, bit_fail_limit)
FANN_GET_SET(float, learning_momentum)
