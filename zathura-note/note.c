#include "plugin.h"

#include <plist/plist.h>
#include <stdio.h>
#include <zip.h>

typedef struct {
	zip_t *zip;
	plist_t session_plist;
	plist_t metadata_plist;
} note_document_t;

// Found by reverse engineering
#define SESSION_OBJECTS_GENERAL_INFO 1
#define SESSION_OBJECTS_FORMAT_INFO 2

// For debugging/reverse engineering
#define INDENT 4
static void plist_dump(plist_t plist, int depth)
{
	for (int i = 0; i < depth * INDENT; i++)
		printf(" ");

	if (PLIST_IS_BOOLEAN(plist)) {
		unsigned char val;
		plist_get_bool_val(plist, &val);
		printf("<bool>%s</bool>\n", val ? "true" : "false");
	} else if (PLIST_IS_UINT(plist)) {
		unsigned long val;
		plist_get_uint_val(plist, &val);
		printf("<uint>%lu</uint>\n", val);
	} else if (PLIST_IS_REAL(plist)) {
		double val;
		plist_get_real_val(plist, &val);
		printf("<real>%f</real>\n", val);
	} else if (PLIST_IS_STRING(plist)) {
		char *val;
		plist_get_string_val(plist, &val);
		printf("<string>%s</string>\n", val);
		free(val);
	} else if (PLIST_IS_ARRAY(plist)) {
		plist_array_iter iter;
		plist_array_new_iter(plist, &iter);
		plist_t val;
		printf("<array>\n");
		int id = 0;
		while (1) {
			plist_array_next_item(plist, iter, &val);
			if (!val)
				break;

			for (int i = 0; i < (depth + 1) * INDENT; i++)
				printf(" ");
			printf("<array_item id=\"%d\">\n", id++);

			plist_dump(val, depth + 2);

			for (int i = 0; i < (depth + 1) * INDENT; i++)
				printf(" ");
			printf("</array_item>\n");
		}
		for (int i = 0; i < depth * INDENT; i++)
			printf(" ");
		printf("</array>\n");
	} else if (PLIST_IS_DICT(plist)) {
		plist_dict_iter iter;
		plist_dict_new_iter(plist, &iter);
		char *key = 0;
		plist_t val;
		printf("<dict>\n");
		int id = 0;
		while (1) {
			plist_dict_next_item(plist, iter, &key, &val);
			if (!key || !val)
				break;

			for (int i = 0; i < (depth + 1) * INDENT; i++)
				printf(" ");
			printf("<dict_item key=\"%s\" id=\"%d\">\n", key, id++);

			plist_dump(val, depth + 2);
			free(key);

			for (int i = 0; i < (depth + 1) * INDENT; i++)
				printf(" ");
			printf("</dict_item>\n");
		}
		for (int i = 0; i < depth * INDENT; i++)
			printf(" ");
		printf("</dict>\n");
	} else if (PLIST_IS_DATE(plist)) {
		int sec, usec;
		plist_get_date_val(plist, &sec, &usec);
		printf("<date>%d</date>\n", sec); // Since 01/01/2001
	} else if (PLIST_IS_DATA(plist)) {
		unsigned long length;
		const char *val = plist_get_data_ptr(plist, &length);
		printf("<data length=\"%lu\">%.*s</data>\n", length, (int)length, val);
	} else if (PLIST_IS_KEY(plist)) {
		char *val;
		plist_get_key_val(plist, &val);
		printf("<key>%s</key>\n", val);
		free(val);
	} else if (PLIST_IS_UID(plist)) {
		unsigned long val;
		plist_get_uid_val(plist, &val);
		printf("<uid>%lu</uid>\n", val);
	}
}

static zathura_error_t plist_load(zip_t *zip, plist_t *plist, const char *root_name,
				  const char *path)
{
	char name[1024] = { 0 };
	snprintf(name, sizeof(name), "%s/%s", root_name, path);
	zip_stat_t stat;
	zip_stat(zip, name, 0, &stat);
	zip_file_t *file = zip_fopen(zip, name, 0);
	if (!file) {
		zip_error_t *err = zip_get_error(zip);
		fprintf(stderr, "Couldn't find '%s' in zip: %s\n", name, zip_error_strerror(err));
		return ZATHURA_ERROR_INVALID_ARGUMENTS;
	}

	void *bin = malloc(stat.size);
	size_t length = zip_fread(file, bin, stat.size);
	if (length < stat.size) {
		fprintf(stderr, "Unexpected size difference\n");
		free(bin);
		return ZATHURA_ERROR_INVALID_ARGUMENTS;
	}

	if (!plist_is_binary(bin, stat.size)) {
		fprintf(stderr, "Unexpected file format of '%s'\n", path);
		free(bin);
		return ZATHURA_ERROR_INVALID_ARGUMENTS;
	}

	plist_from_bin(bin, stat.size, plist);
	free(bin);
	return ZATHURA_ERROR_OK;
}

static plist_t plist_session_objects(plist_t session_plist)
{
	plist_t objects = plist_dict_get_item(session_plist, "$objects");
	if (!PLIST_IS_ARRAY(objects)) {
		fprintf(stderr, "Invalid objects type\n");
		return 0;
	}
	return objects;
}

static plist_t plist_session_format_information(plist_t session_plist)
{
	plist_t objects = plist_session_objects(session_plist);
	if (!objects)
		return 0;

	plist_t format = plist_array_get_item(objects, SESSION_OBJECTS_FORMAT_INFO);
	if (!PLIST_IS_DICT(format)) {
		fprintf(stderr, "Invalid format information type\n");
		return 0;
	}
	return format;
}

static plist_t plist_handwriting_overlay(plist_t session_plist)
{
	plist_t objects = plist_session_objects(session_plist);
	if (!objects)
		return 0;

	plist_t format = plist_array_get_item(objects, SESSION_OBJECTS_FORMAT_INFO);
	if (!PLIST_IS_DICT(format)) {
		fprintf(stderr, "Invalid format information\n");
		return 0;
	}

	plist_t overlay_pointer = plist_dict_get_item(format, "Handwriting Overlay");
	if (!PLIST_IS_UID(overlay_pointer)) {
		fprintf(stderr, "Invalid handwriting overlay pointer\n");
		return 0;
	}

	unsigned long index;
	plist_get_uid_val(overlay_pointer, &index);

	plist_t overlay_info = plist_array_get_item(objects, index);
	if (!PLIST_IS_DICT(overlay_info)) {
		fprintf(stderr, "Invalid overlay info item\n");
		return 0;
	}

	plist_t spatial_hash = plist_dict_get_item(overlay_info, "SpatialHash");
	if (!PLIST_IS_UID(spatial_hash)) {
		fprintf(stderr, "Invalid spatial hash\n");
		return 0;
	}

	plist_get_uid_val(spatial_hash, &index);

	plist_t overlay = plist_array_get_item(objects, index);
	if (!PLIST_IS_DICT(overlay)) {
		fprintf(stderr, "Invalid handwriting overlay\n");
		return 0;
	}

	return overlay;
}

static float plist_page_width(plist_t session_plist)
{
	plist_t objects = plist_session_objects(session_plist);
	if (!objects)
		return 0;

	plist_t format = plist_array_get_item(objects, SESSION_OBJECTS_FORMAT_INFO);
	if (!PLIST_IS_DICT(format)) {
		fprintf(stderr, "Invalid format information\n");
		return 0;
	}

	plist_t reflow_state_pointer = plist_dict_get_item(format, "reflowState");
	if (!PLIST_IS_UID(reflow_state_pointer)) {
		fprintf(stderr, "Invalid reflow state pointer\n");
		return 0;
	}

	unsigned long index;
	plist_get_uid_val(reflow_state_pointer, &index);

	plist_t reflow_state = plist_array_get_item(objects, index);
	if (!PLIST_IS_DICT(reflow_state)) {
		fprintf(stderr, "Invalid reflow state item\n");
		return 0;
	}

	plist_t page_width = plist_dict_get_item(reflow_state, "pageWidthInDocumentCoordsKey");
	if (!PLIST_IS_REAL(page_width)) {
		fprintf(stderr, "Invalid page width\n");
		return 0;
	}

	double val;
	plist_get_real_val(page_width, &val);
	return val;
}

GIRARA_HIDDEN zathura_error_t note_document_open(zathura_document_t *document)
{
	zathura_error_t error = ZATHURA_ERROR_OK;

	if (!document) {
		error = ZATHURA_ERROR_INVALID_ARGUMENTS;
		return error;
	}

	int zip_err;
	zip_t *zip =
		zip_open(zathura_document_get_path(document), ZIP_CHECKCONS | ZIP_RDONLY, &zip_err);
	if (!zip || zip_err) {
		zip_error_t *err = zip_get_error(zip);
		fprintf(stderr, "Couldn't open .note zip: (%d): %s\n", zip_err,
			zip_error_strerror(err));
		return ZATHURA_ERROR_INVALID_ARGUMENTS;
	}

	char *root_name;
	zip_stat_t root_stat;
	if (!zip_stat_index(zip, 0, 0, &root_stat)) {
		int length = strlen(root_stat.name);
		root_name = malloc(length + 1);
		strcpy(root_name, root_stat.name);
		strtok(root_name, "/");
		root_name[length] = 0;
	} else {
		// Wtf? No files?
		return ZATHURA_ERROR_INVALID_ARGUMENTS;
	}

	note_document_t *note_document = malloc(sizeof(*note_document));

	// Load Session.plist from zip
	zathura_error_t session_error =
		plist_load(zip, &note_document->session_plist, root_name, "Session.plist");
	if (session_error != ZATHURA_ERROR_OK) {
		free(note_document);
		free(root_name);
		return session_error;
	}

	// Load metadata.plist from zip
	zathura_error_t metadata_error =
		plist_load(zip, &note_document->metadata_plist, root_name, "metadata.plist");
	if (metadata_error != ZATHURA_ERROR_OK) {
		free(note_document);
		free(root_name);
		return metadata_error;
	}

	note_document->zip = zip;

	zathura_document_set_data(document, note_document);
	zathura_document_set_number_of_pages(document, 1); // TODO: Get page count

	free(root_name);
	return ZATHURA_ERROR_OK;
}

GIRARA_HIDDEN zathura_error_t note_document_free(zathura_document_t *document, void *data)
{
	if (!data)
		return ZATHURA_ERROR_OK;

	note_document_t *note_document = data;
	zip_close(note_document->zip);
	return ZATHURA_ERROR_OK;
}

GIRARA_HIDDEN zathura_error_t note_page_init(zathura_page_t *page)
{
	note_document_t *note_document = zathura_document_get_data(zathura_page_get_document(page));
	float width = plist_page_width(note_document->session_plist);
	if (width < 1)
		return ZATHURA_ERROR_NOT_IMPLEMENTED;

	zathura_page_set_width(page, width);
	zathura_page_set_height(page, width * 1.41); // Always A4?

	return ZATHURA_ERROR_OK;
}

GIRARA_HIDDEN zathura_error_t note_page_clear(zathura_page_t *page, void *data)
{
	return ZATHURA_ERROR_OK;
}

GIRARA_HIDDEN zathura_error_t note_page_render_cairo(zathura_page_t *page, void *data,
						     cairo_t *cairo, bool printing)
{
	if (printing)
		return ZATHURA_ERROR_NOT_IMPLEMENTED;

	float width = zathura_page_get_width(page);
	float height = zathura_page_get_height(page);

	note_document_t *note_document = zathura_document_get_data(zathura_page_get_document(page));
	plist_t overlay = plist_handwriting_overlay(note_document->session_plist);
	if (!overlay)
		return ZATHURA_ERROR_NOT_IMPLEMENTED;

	plist_t points_data = plist_dict_get_item(overlay, "curvespoints");
	if (!PLIST_IS_DATA(points_data))
		return ZATHURA_ERROR_NOT_IMPLEMENTED;

	unsigned long points_length;
	const char *points_chars = plist_get_data_ptr(points_data, &points_length);
	if (!points_chars)
		return ZATHURA_ERROR_NOT_IMPLEMENTED;
	float *points = (float *)points_chars;

	cairo_set_source_rgba(cairo, 0xff, 0, 0, 1);
	cairo_set_line_width(cairo, 1);
	for (unsigned long i = 0; i < points_length; i += 2) {
		float x = points[i];
		float y = points[i + 1];
		if (x > width || y > height)
			continue;
		cairo_line_to(cairo, points[i], points[i + 1]);
	}
	cairo_close_path(cairo);
	cairo_stroke(cairo);

	return ZATHURA_ERROR_OK;
}
