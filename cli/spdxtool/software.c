/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 *​ Copyright (c) 2025 The FreeBSD Foundation
 *​
 *​ Portions of this software were developed by
 * Tuukka Pasanen <tuukka.pasanen@ilmi.fi> under sponsorship from
 * the FreeBSD Foundation
 */

#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "serialize.h"
#include "software.h"
#include "core.h"

/*
 * !doc
 *
 * .. c:function:: spdxtool_software_sbom_t *spdxtool_software_sbom_new(pkgconf_client_t *client, const char *spdx_id, const char *creation_id, const char *sbom_type)
 *
 *    Create new /Software/Sbom struct
 *
 *    :param pkgconf_client_t *client: The pkgconf client being accessed.
 *    :param const char *spdx_id: spdxId for this SBOM element
 *    :param const char *creation_id: id for CreationInfo
 *    :param const char *sbom_type: Sbom types can be found SPDX documention
 *    :return: NULL if some problem occurs and Sbom struct if not
 */
spdxtool_software_sbom_t *
spdxtool_software_sbom_new(pkgconf_client_t *client, const char *spdx_id, const char *creation_id, const char *sbom_type)
{
	spdxtool_software_sbom_t *sbom = NULL;

	if(!client || !spdx_id || !creation_id || !sbom_type)
		return NULL;

	sbom = calloc(1, sizeof(spdxtool_software_sbom_t));
	if(!sbom)
		goto oom;

	sbom->type = "software_Sbom";
	if (!(sbom->spdx_id = strdup(spdx_id)))
		goto oom;
	if (!(sbom->creation_info = strdup(creation_id)))
		goto oom;
	if (!(sbom->sbom_type = strdup(sbom_type)))
		goto oom;

	return sbom;

oom:
	pkgconf_error(client, "spdxtool_software_sbom_new: out of memory");
	spdxtool_software_sbom_free(sbom);
	return NULL;
}

/*
 * !doc
 *
 * .. c:function:: void spdxtool_software_sbom_free(spdxtool_software_sbom_t *sbom)
 *
 *    Free /Software/Sbom struct
 *
 *    :param spdxtool_software_sbom_t *sbom: Sbom struct to be freed.
 *    :return: nothing
 */
void
spdxtool_software_sbom_free(spdxtool_software_sbom_t *sbom)
{

	if(!sbom)
		return;

	free(sbom->spdx_id);
	free(sbom->creation_info);
	free(sbom->sbom_type);

	free(sbom);
}

/*
 * !doc
 *
 * .. c:function:: spdxtool_serialize_value_t spdxtool_software_sbom_to_object(pkgconf_client_t *client, spdxtool_software_sbom_t *sbom)
 *
 *    Serialize /Software/Sbom struct to a JSON value tree. As a side effect,
 *    the package associated with the SBOM's rootElement is registered on the
 *    document via spdxtool_core_spdx_document_add_package, and relationship
 *    element IDs are registered via spdxtool_core_spdx_document_add_element.
 *
 *    :param pkgconf_client_t *client: The pkgconf client being accessed.
 *    :param spdxtool_software_sbom_t *sbom: Sbom struct to be serialized.
 *    :return: spdxtool_serialize_value_t representing the Sbom object.
 */
spdxtool_serialize_value_t *
spdxtool_software_sbom_to_object(pkgconf_client_t *client, spdxtool_software_sbom_t *sbom)
{
	bool ok;
	spdxtool_serialize_value_t *ret = NULL;
	spdxtool_serialize_object_list_t *object_list = NULL;
	spdxtool_serialize_array_t *sbom_type_array = NULL, *root_element_array = NULL, *element_array = NULL;
	char *spdx_id = spdxtool_util_tuple_lookup(client, &sbom->rootElement->vars, "spdxId");
	if (!spdx_id)
		goto oom;

	object_list = spdxtool_serialize_object_list_new();
	if (!object_list)
		goto oom;

	// software_sbomType array
	sbom_type_array = spdxtool_serialize_array_new();
	if (!sbom_type_array)
		goto oom;

	if (!spdxtool_serialize_array_add_string(sbom_type_array, sbom->sbom_type))
		goto oom;

	// rootElement array
	root_element_array = spdxtool_serialize_array_new();
	if (!root_element_array)
		goto oom;

	if (!spdxtool_serialize_array_add_string(root_element_array, spdx_id))
		goto oom;

	free(spdx_id);
	spdx_id = NULL;

	// element array
	element_array = spdxtool_serialize_array_new();
	if (!element_array)
		goto oom;

	pkgconf_node_t *node = NULL;
	PKGCONF_FOREACH_LIST_ENTRY(sbom->rootElement->required.head, node)
	{
		pkgconf_dependency_t *dep = node->data;
		pkgconf_pkg_t *match = dep->match;
		pkgconf_buffer_t relationship_buf = PKGCONF_BUFFER_INITIALIZER;

		pkgconf_buffer_append_fmt(&relationship_buf, "%s/dependsOn/%s", sbom->rootElement->id, match->id);
		char *relationship_str = pkgconf_buffer_freeze(&relationship_buf);
		if (!relationship_str)
			goto oom;

		char *spdx_id_relation = spdxtool_util_get_spdx_id_string(client, "Relationship", relationship_str);
		free(relationship_str);
		if (!spdx_id_relation)
			goto oom;

		ok = spdxtool_serialize_array_add_string(element_array, spdx_id_relation) &&
			spdxtool_core_spdx_document_add_element(client, sbom->spdx_document, spdx_id_relation);
		free(spdx_id_relation);
		if (!ok)
			goto oom;
	}

	char *value = spdxtool_util_tuple_lookup(client, &sbom->rootElement->vars, "hasDeclaredLicense");
	if (value)
	{
		ok = spdxtool_serialize_array_add_string(element_array, value) &&
			spdxtool_core_spdx_document_add_element(client, sbom->spdx_document, value);
		free(value);
		if (!ok)
			goto oom;
	}

	value = spdxtool_util_tuple_lookup(client, &sbom->rootElement->vars, "hasConcludedLicense");
	if (value)
	{
		ok = spdxtool_serialize_array_add_string(element_array, value) &&
			spdxtool_core_spdx_document_add_element(client, sbom->spdx_document, value);
		free(value);
		if (!ok)
			goto oom;
	}

	ok = spdxtool_serialize_object_add_string(object_list, "type", sbom->type) &&
		spdxtool_serialize_object_add_string(object_list, "creationInfo", sbom->creation_info) &&
		spdxtool_serialize_object_add_string(object_list, "spdxId", sbom->spdx_id);
	if (!ok)
	{
		goto oom;
	}

	ok = spdxtool_serialize_object_add_array(object_list, "software_sbomType", sbom_type_array);
	sbom_type_array = NULL;
	if (!ok)
		goto oom;

	ok = spdxtool_serialize_object_add_array(object_list, "rootElement", root_element_array);
	root_element_array = NULL;
	if (!ok)
		goto oom;

	ok = spdxtool_serialize_object_add_array(object_list, "element", element_array);
	element_array = NULL;
	if (!ok)
		goto oom;

	// register package for serialization as a sibling in the graph
	spdxtool_core_spdx_document_add_package(client, sbom->spdx_document, sbom->rootElement);

	ret = spdxtool_serialize_value_object(object_list);
	object_list = NULL;

oom:
	if (!ret)
		pkgconf_error(client, "spdxtool_software_sbom_to_object: out of memory");

	free(spdx_id);
	spdxtool_serialize_object_list_free(object_list);
	spdxtool_serialize_array_free(sbom_type_array);
	spdxtool_serialize_array_free(root_element_array);
	spdxtool_serialize_array_free(element_array);

	return ret;
}

/*
 * !doc
 *
 * .. c:function:: spdxtool_serialize_value_t *spdxtool_software_package_to_object(pkgconf_client_t *client, pkgconf_pkg_t *pkg, spdxtool_core_spdx_document_t *spdx)
 *
 *    Serialize /Software/Package struct to a JSON value tree. As a side effect,
 *    any license and dependency relationships generated during serialization are
 *    added to the document via spdxtool_core_spdx_document_add_relationship.
 *
 *    :param pkgconf_client_t *client: The pkgconf client being accessed.
 *    :param pkgconf_pkg_t *pkg: Package struct to be serialized.
 *    :param spdxtool_core_spdx_document_t *spdx: SpdxDocument to which generated relationships are added.
 *    :return: spdxtool_serialize_value_t * representing the Package object.
 */
spdxtool_serialize_value_t *
spdxtool_software_package_to_object(pkgconf_client_t *client, pkgconf_pkg_t *pkg, spdxtool_core_spdx_document_t *spdx)
{
	bool ok;
	spdxtool_serialize_value_t *ret = NULL;
	const char *errstr = "out of memory";

	char *creation_info = NULL, *spdx_id = NULL, *agent = NULL;
	char *spdx_id_license = NULL, *tuple_license = NULL;
	spdxtool_serialize_array_t *originated_by = NULL;
	spdxtool_serialize_object_list_t *object_list = NULL;

	creation_info = spdxtool_util_tuple_lookup(client, &pkg->vars, "creationInfo");
	spdx_id = spdxtool_util_tuple_lookup(client, &pkg->vars, "spdxId");
	agent = spdxtool_util_tuple_lookup(client, &pkg->vars, "agent");
	if (!creation_info || !spdx_id || !agent)
	{
		errstr = "could not gather object info";
		goto err;
	}

	object_list = spdxtool_serialize_object_list_new();
	if (!object_list)
		goto err;

	originated_by = spdxtool_serialize_array_new();
	if (!originated_by)
		goto err;

	if (!spdxtool_serialize_array_add_string(originated_by, agent))
		goto err;

	ok = spdxtool_serialize_object_add_string(object_list, "type", "software_Package") &&
		spdxtool_serialize_object_add_string(object_list, "creationInfo", creation_info) &&
		spdxtool_serialize_object_add_string(object_list, "spdxId", spdx_id) &&
		spdxtool_serialize_object_add_string(object_list, "name", pkg->realname);
	if (!ok)
		goto err;

	ok = spdxtool_serialize_object_add_array(object_list, "originatedBy", originated_by);
	originated_by = NULL;
	if (!ok)
		goto err;

	ok = spdxtool_serialize_object_add_string(object_list, "software_copyrightText", "NOASSERTION") &&
		spdxtool_serialize_object_add_string(object_list, "software_packageVersion", pkg->version);
	if (!ok)
		goto err;

	spdx_id_license = spdxtool_util_get_spdx_id_string(client, "simplelicensing_LicenseExpression", pkg->license);
	if (!spdx_id_license)
	{
		errstr = "could not get license";
		goto err;
	}

	tuple_license = spdxtool_util_tuple_lookup(client, &pkg->vars, "hasDeclaredLicense");
	if (tuple_license)
	{
		spdxtool_core_relationship_t *relationship = spdxtool_core_relationship_new(client, creation_info, tuple_license, spdx_id, spdx_id_license, "hasDeclaredLicense");
		free(tuple_license);
		tuple_license = NULL;
		if (relationship)
			spdxtool_core_spdx_document_add_relationship(client, spdx, relationship);
	}

	tuple_license = spdxtool_util_tuple_lookup(client, &pkg->vars, "hasConcludedLicense");
	if (tuple_license)
	{
		spdxtool_core_relationship_t *relationship = spdxtool_core_relationship_new(client, creation_info, tuple_license, spdx_id, spdx_id_license, "hasConcludedLicense");
		free(tuple_license);
		tuple_license = NULL;
		if (relationship)
			spdxtool_core_spdx_document_add_relationship(client, spdx, relationship);
	}

	free(spdx_id_license);
	spdx_id_license = NULL;

	pkgconf_node_t *node = NULL;
	PKGCONF_FOREACH_LIST_ENTRY(pkg->required.head, node)
	{
		pkgconf_dependency_t *dep = node->data;
		pkgconf_pkg_t *match = dep->match;
		pkgconf_buffer_t relationship_buf = PKGCONF_BUFFER_INITIALIZER;

		pkgconf_buffer_append_fmt(&relationship_buf, "%s/dependsOn/%s", pkg->id, match->id);
		char *relationship_str = pkgconf_buffer_freeze(&relationship_buf);
		if (!relationship_str)
			goto err;

		char *spdx_id_relation = spdxtool_util_get_spdx_id_string(client, "Relationship", relationship_str);
		free(relationship_str);
		if (!spdx_id_relation)
			goto err;

		char *spdx_id_package = spdxtool_util_get_spdx_id_string(client, "Package", match->id);
		spdxtool_core_relationship_t *relationship = spdxtool_core_relationship_new(client, creation_info, spdx_id_relation, spdx_id, spdx_id_package, "dependsOn");
		free(spdx_id_relation);
		free(spdx_id_package);
		if (relationship)
			spdxtool_core_spdx_document_add_relationship(client, spdx, relationship);
	}

	ret = spdxtool_serialize_value_object(object_list);
	object_list = NULL;

err:
	if (ret == NULL)
		pkgconf_error(client, "spdxtool_software_package_to_object: %s", errstr);
	free(creation_info);
	free(spdx_id);
	free(agent);
	free(spdx_id_license);
	free(tuple_license);
	spdxtool_serialize_array_free(originated_by);
	spdxtool_serialize_object_list_free(object_list);
	return ret;
}
