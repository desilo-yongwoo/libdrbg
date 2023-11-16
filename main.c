/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#include <vector>

#include <pybind11/stl.h>
#include <pybind11/pybind11.h>
#include "drbg.h"
#include "drbg_common.h"

namespace py = pybind11;

drbg_ctx* generate_drbg(std::vector<unsigned char> entropy_in, std::vector<unsigned char> nonce_in)
{

	drbg_ctx* drbg = (drbg_ctx*)malloc(sizeof(drbg_ctx));
	drbg_error ret;
	const unsigned char pers_string[] = "DRBG_PERS";
	unsigned char* entropy = &entropy_in[0];
	unsigned char* nonce = &nonce_in[0];
	drbg_options opt;
	uint32_t security_strength;

	(void)pers_string;
	(void)entropy;
	(void)nonce;
	(void)opt;
	(void)security_strength;
	
	DRBG_CTR_OPTIONS_INIT(opt, CTR_DRBG_BC_AES256, true, 0);
	ret = drbg_instantiate_with_user_entropy(drbg, pers_string, sizeof(pers_string) - 1, entropy, 32, nonce, 16, NULL, true, DRBG_CTR, &opt);
	if(ret != DRBG_OK){
		goto err;
	}
	
	ret = drbg_get_drbg_strength(drbg, &security_strength);
	if(ret != DRBG_OK){
		goto err;
	}
	return drbg;
err:
	return drbg;
}
std::vector<uint64_t> run_drbg(drbg_ctx *drbg)
{
	unsigned char output[8*4096] = { 0 };
	uint32_t max_len = 8*4096;
	
	(void)output;
	(void)max_len;
	
	std::vector<uint64_t> prng_updated;
	drbg_error ret;
	
	ret = drbg_generate(drbg, NULL, 0, output, (max_len < sizeof(output)) ? max_len : sizeof(output), true);
	
	if(ret != DRBG_OK){
		goto err;
	}
	
	for(int i=0; i<4096; i++)
	{
		uint64_t prng_updated_part = 0;
		for(int j=7;j>=0;j--)
		{
			prng_updated_part<<=8;
			prng_updated_part+=(uint64_t(output[8*i+j]));
		}
		prng_updated.push_back(prng_updated_part);
	}
	return prng_updated;
err:
	return prng_updated;
}

PYBIND11_MODULE(drbg, m){
	py::class_<drbg_ctx>(m, "drbg_ctx")
        .def(py::init<>())
        .def_readwrite("magic", &drbg_ctx::magic)
        .def_readwrite("is_instantiated", &drbg_ctx::is_instantiated)
        .def_readwrite("type", &drbg_ctx::type)
        .def_readwrite("engine_magic", &drbg_ctx::engine_magic)
        .def_readwrite("drbg_strength", &drbg_ctx::drbg_strength)
        .def_readwrite("min_entropy_input_length", &drbg_ctx::min_entropy_input_length)
        .def_readwrite("max_entropy_input_length", &drbg_ctx::max_entropy_input_length)
        .def_readwrite("max_pers_string_length", &drbg_ctx::max_pers_string_length)
        .def_readwrite("max_addin_length", &drbg_ctx::max_addin_length)
        .def_readwrite("max_asked_length", &drbg_ctx::max_asked_length)
        .def_readwrite("reseed_counter", &drbg_ctx::reseed_counter)
        .def_readwrite("reseed_interval", &drbg_ctx::reseed_interval)
        .def_readwrite("engine_is_instantiated", &drbg_ctx::engine_is_instantiated)
        .def_readwrite("prediction_resistance", &drbg_ctx::prediction_resistance)
	.def_readwrite("reseed_required_flag", &drbg_ctx::reseed_required_flag)
        .def_readwrite("methods", &drbg_ctx::methods)
        .def_readwrite("data", &drbg_ctx::data);

	m.def("generate_drbg", &generate_drbg, "Generate drbg with given CRP");
	m.def("run_drbg", &run_drbg, "Run drbg with given drbg object");

}
