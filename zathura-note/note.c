#include "plugin.h"

#include <plist/plist.h>
#include <stdio.h>
#include <zip.h>

typedef struct {
	zip_t *zip;
	plist_t objects;
	double width, height; // Page size is constant
} note_document_t;

// Found by reverse engineering
#define SESSION_OBJECTS_GENERAL_INFO 1
#define SESSION_OBJECTS_LAYOUT_INFO 2

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
		size_t val;
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
		printf("<array>\n");
		int id = 0;
		while (1) {
			plist_t val;
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
		size_t length;
		const char *val = plist_get_data_ptr(plist, &length);
		(void)val;
		printf("<data length=\"%lu\">...</data>\n", length);
	} else if (PLIST_IS_KEY(plist)) {
		char *val;
		plist_get_key_val(plist, &val);
		printf("<key>%s</key>\n", val);
		free(val);
	} else if (PLIST_IS_UID(plist)) {
		size_t val;
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

static const void *plist_dict_get_data(plist_t node, const char *name, size_t *length)
{
	plist_t data = plist_dict_get_item(node, name);
	if (!PLIST_IS_DATA(data))
		return 0;
	return plist_get_data_ptr(data, length);
}

// Magic unicorn function to reduce ugliness of plist
static plist_t plist_access(plist_t plist, int length, ...)
{
	if (!PLIST_IS_ARRAY(plist)) {
		fprintf(stderr, "Only main $objects array is supported\n");
		return 0;
	}

	va_list va;
	va_start(va, length);

	unsigned long uid = 0;
	const char **ptr;
	plist_t current = plist;
	int i;
	for (i = 0; i < length && current; i++) {
		plist_type type = plist_get_node_type(current);
		switch (type) {
		case PLIST_ARRAY:
			current = plist_array_get_item(current, va_arg(va, int));
			break;
		case PLIST_DICT:
			current = plist_dict_get_item(current, va_arg(va, const char *));
			break;
		case PLIST_UID: // Automatic tracing!
			plist_get_uid_val(current, &uid);
			current = plist_array_get_item(plist, uid);
			i--; // UID doesn't count
			break;
		case PLIST_DATA:
			if (i + 2 < length)
				fprintf(stderr, "Unexpected data\n");
			ptr = va_arg(va, const char **);
			*ptr = plist_get_data_ptr(current, va_arg(va, unsigned long *));
			goto end;
		case PLIST_STRING:
			if (i + 2 < length)
				fprintf(stderr, "Unexpected string\n");
			ptr = va_arg(va, const char **);
			*ptr = plist_get_string_ptr(current, va_arg(va, unsigned long *));
			goto end;
		case PLIST_BOOLEAN:
			if (i + 1 < length)
				fprintf(stderr, "Unexpected bool\n");
			plist_get_bool_val(current, va_arg(va, unsigned char *));
			goto end;
		case PLIST_UINT:
			if (i + 1 < length)
				fprintf(stderr, "Unexpected uint\n");
			plist_get_uint_val(current, va_arg(va, unsigned long *));
			goto end;
		case PLIST_REAL:
			if (i + 1 < length)
				fprintf(stderr, "Unexpected real\n");
			plist_get_real_val(current, va_arg(va, double *));
			goto end;
		default:
			fprintf(stderr, "Fatal failure in access loop\n");
		}
	}

	if (i != length)
		fprintf(stderr, "Unexptected end of access loop\n");

end:
	// Resolve current if UID
	if (PLIST_IS_UID(current)) {
		plist_get_uid_val(current, &uid);
		current = plist_array_get_item(plist, uid);
	}

	va_end(va);

	// TODO: Exit entire zathura in these conditions? Hmmm
	if (!current)
		fprintf(stderr, "Even more fatal failure in access loop\n");

	return current;
}

static plist_t plist_handwriting_overlay(plist_t objects)
{
	plist_t overlay = plist_access(objects, 3, SESSION_OBJECTS_LAYOUT_INFO,
				       "Handwriting Overlay", "SpatialHash");

	if (!PLIST_IS_DICT(overlay)) {
		fprintf(stderr, "Invalid handwriting overlay\n");
		return 0;
	}

	return overlay;
}

// TODO: Find more elegant solution for page count (there doesn't seem to be)
static int plist_page_count(plist_t objects, double page_height)
{
	const float *curves = 0;
	size_t curves_length = 0;
	plist_access(objects, 6, SESSION_OBJECTS_LAYOUT_INFO, "Handwriting Overlay", "SpatialHash",
		     "curvespoints", &curves, &curves_length);

	// Find highest y curve-point
	double max = 0;
	for (size_t i = 0; i < curves_length / sizeof(*curves); i += 2)
		if (curves[i + 1] > max)
			max = curves[i + 1];

	return (int)(max / page_height) + 1;
}

static float plist_page_ratio(plist_t objects)
{
	float ratio = 1.414; // DIN ratio because why not

	const char *type;
	size_t type_length = 0;
	plist_access(objects, 6, SESSION_OBJECTS_GENERAL_INFO,
		     "NBNoteTakingSessionDocumentPaperLayoutModelKey", "documentPaperAttributes",
		     "paperIdentifier", &type, &type_length);

	if (!memcmp(type, "Legacy:13", type_length))
		ratio = 1.3; // Or does 13 refer to 13x19"??
	else if (!memcmp(type, "Legacy:0", type_length))
		// 0 means page not renderable (?)
		fprintf(stderr, "Page identifies as not renderable, please report\n");
	else
		fprintf(stderr, "Unknown paper identifier, please report: %s\n", type);

	return ratio;
}

static float plist_page_width(plist_t objects)
{
	double val;
	plist_access(objects, 4, SESSION_OBJECTS_LAYOUT_INFO, "reflowState",
		     "pageWidthInDocumentCoordsKey", &val);

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
		strncpy(root_name, root_stat.name, length);
		strtok(root_name, "/");
		root_name[length] = 0;
	} else {
		// Wtf? No files?
		return ZATHURA_ERROR_INVALID_ARGUMENTS;
	}

	note_document_t *note_document = malloc(sizeof(*note_document));

	// Load $objects from Session.plist from zip
	plist_t session_plist;
	zathura_error_t session_error = plist_load(zip, &session_plist, root_name, "Session.plist");
	if (session_error != ZATHURA_ERROR_OK) {
		free(note_document);
		free(root_name);
		return session_error;
	}
	note_document->objects = plist_dict_get_item(session_plist, "$objects");
	if (!PLIST_IS_ARRAY(note_document->objects)) {
		fprintf(stderr, "Invalid objects type\n");
		free(root_name);
		return ZATHURA_ERROR_NOT_IMPLEMENTED;
	}

	note_document->zip = zip;

	note_document->width = plist_page_width(note_document->objects);
	if (note_document->width < 1) {
		fprintf(stderr, "Setting invalid width %f to 500\n", note_document->width);
		note_document->width = 500;
	}
	note_document->height = note_document->width * plist_page_ratio(note_document->objects);

	zathura_document_set_data(document, note_document);
	zathura_document_set_number_of_pages(document, plist_page_count(note_document->objects,
									note_document->height));

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
	zathura_page_set_width(page, note_document->width);
	zathura_page_set_height(page, note_document->height);

	return ZATHURA_ERROR_OK;
}

GIRARA_HIDDEN zathura_error_t note_page_clear(zathura_page_t *page, void *data)
{
	return ZATHURA_ERROR_OK;
}

static void note_page_render_object(cairo_t *cairo, plist_t objects, int index)
{
	char *position = 0;
	size_t position_length = 0;
	plist_access(objects, 4, index, "documentContentOrigin", &position, &position_length);
	printf("%.*s\n", (int)position_length, position);
}

// It doesn't really matter if something in here fails
static void note_page_render_objects(cairo_t *cairo, plist_t objects)
{
	plist_t objects_array =
		plist_access(objects, 3, SESSION_OBJECTS_LAYOUT_INFO, "mediaObjects", "NS.objects");

	plist_array_iter iter;
	plist_array_new_iter(objects_array, &iter);
	while (1) {
		plist_t val;
		plist_array_next_item(objects_array, iter, &val);
		if (!val)
			break;

		size_t index;
		plist_get_uid_val(val, &index);
		note_page_render_object(cairo, objects, index);
	}
}

GIRARA_HIDDEN zathura_error_t note_page_render_cairo(zathura_page_t *page, void *data,
						     cairo_t *cairo, bool printing)
{
	if (printing)
		return ZATHURA_ERROR_NOT_IMPLEMENTED;

	note_document_t *note_document = zathura_document_get_data(zathura_page_get_document(page));
	plist_t overlay = plist_handwriting_overlay(note_document->objects);
	if (!overlay)
		return ZATHURA_ERROR_NOT_IMPLEMENTED;

	/* plist_dump(note_document->session_plist, 0); */
	/* return ZATHURA_ERROR_OK; */

	double height = zathura_page_get_height(page);
	unsigned int number = zathura_page_get_index(page);
	double page_start = height * number;
	double page_end = height * (number + 1);

	// Render all media objects (images, ...)
	note_page_render_objects(cairo, note_document->objects);

	// Array of points on curve
	size_t curves_length = 0;
	const float *curves = plist_dict_get_data(overlay, "curvespoints", &curves_length);

	// Specifies the number of points of a curve (using index of *curves)
	size_t curves_num_length = 0;
	const unsigned int *curves_num =
		plist_dict_get_data(overlay, "curvesnumpoints", &curves_num_length);

	// Width of curves
	size_t curves_width_length = 0;
	const float *curves_width =
		plist_dict_get_data(overlay, "curveswidth", &curves_width_length);

	// Colors of curves
	size_t curves_colors_length = 0;
	const char *curves_colors =
		plist_dict_get_data(overlay, "curvescolors", &curves_colors_length);

	// TODO: Fallback?
	if (!curves || !curves_length || !curves_num || !curves_num_length || !curves_colors ||
	    !curves_colors_length || !curves_width || !curves_width_length)
		return ZATHURA_ERROR_NOT_IMPLEMENTED;

	size_t limit = curves_num_length / sizeof(*curves_num);
	unsigned int pos = 0;
	for (size_t i = 0; i < limit; i++) {
		const unsigned int length = curves_num[i];
		const char *color = &curves_colors[i * 4];
		cairo_set_source_rgba(cairo, (float)(color[0] & 0xff) / 255,
				      (float)(color[1] & 0xff) / 255,
				      (float)(color[2] & 0xff) / 255,
				      (float)(color[3] & 0xff) / 255);
		cairo_set_line_width(cairo, curves_width[i]);

		if (curves[pos + 1] >= page_start && curves[pos + 1] <= page_end)
			cairo_move_to(cairo, curves[pos], curves[pos + 1] - page_start);

		// TODO: Render as bezier curves
		for (unsigned int j = pos; j < pos + length * 2; j += 2)
			if (curves[j + 1] >= page_start && curves[j + 1] <= page_end)
				cairo_line_to(cairo, curves[j], curves[j + 1] - page_start);

		cairo_stroke(cairo);
		pos += length * 2;
	}

	return ZATHURA_ERROR_OK;
}
