// Copyright (c) 2021 Marvin Borner

#include "plugin.h"

#include <plist/plist.h>
#include <stdio.h>
#include <zip.h>

#include <jpeglib.h>

// Data struct for entire document
typedef struct {
	zip_t *zip;
	plist_t objects;
	char *root_name;
	double width, height; // Page size is constant
} note_document_t;

// Data struct for single page
typedef struct {
	double start, end;
	cairo_t *cairo;
	zathura_page_t *page;
} note_page_t;

// Found by reverse engineering
#define SESSION_OBJECTS_GENERAL_INFO 1
#define SESSION_OBJECTS_GLOBAL_TEXT_STORE 2

/**
 * Zip wrappers/utilities
 */

static void zip_load(zip_t *zip, const char *root_name, const char *path, void **buf,
		     size_t *length)
{
	char name[1024] = { 0 };
	snprintf(name, sizeof(name), "%s/%s", root_name, path);
	zip_stat_t stat;
	zip_stat(zip, name, 0, &stat);
	zip_file_t *file = zip_fopen(zip, name, 0);
	if (!file) {
		zip_error_t *err = zip_get_error(zip);
		fprintf(stderr, "Couldn't find '%s' in zip: %s\n", name, zip_error_strerror(err));
		*buf = 0;
		*length = 0;
		return;
	}

	*buf = malloc(stat.size);
	*length = zip_fread(file, *buf, stat.size);
	if (*length < stat.size) {
		fprintf(stderr, "Unexpected size difference\n");
		free(*buf);
		*buf = 0;
		*length = 0;
		return;
	}
}

/**
 * Plist wrappers/utilities
 */

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
	void *bin;
	size_t length;
	zip_load(zip, root_name, path, &bin, &length);

	if (!bin || !length || !plist_is_binary(bin, length)) {
		fprintf(stderr, "Unexpected file format of '%s'\n", path);
		free(bin);
		return ZATHURA_ERROR_INVALID_ARGUMENTS;
	}

	plist_from_bin(bin, length, plist);
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
	const char **ptr, *dict_key;
	plist_t current = plist;
	int i, array_index;
	for (i = 0; i < length && current; i++) {
		plist_type type = plist_get_node_type(current);
		switch (type) {
		case PLIST_ARRAY:
			array_index = va_arg(va, int);
			current = plist_array_get_item(current, array_index);
			if (!current)
				fprintf(stderr, "Couldn't find %d in array\n", array_index);
			break;
		case PLIST_DICT:
			dict_key = va_arg(va, const char *);
			current = plist_dict_get_item(current, dict_key);
			if (!current)
				fprintf(stderr, "Couldn't find '%s' in dict\n", dict_key);
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
			fprintf(stderr, "Unknown plist type in access loop\n");
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
		fprintf(stderr, "Fatal failure in access loop\n");

	return current;
}

static plist_t plist_handwriting_overlay(plist_t objects)
{
	plist_t overlay = plist_access(objects, 3, SESSION_OBJECTS_GLOBAL_TEXT_STORE,
				       "Handwriting Overlay", "SpatialHash");

	if (!PLIST_IS_DICT(overlay)) {
		fprintf(stderr, "Invalid handwriting overlay\n");
		return 0;
	}

	return overlay;
}

// Converts the strange "{42.123, 69.123}" format to respective floats
static void plist_string_to_floats(const char *string, float *a, float *b)
{
	char *end;
	*a = strtof(string + 1, &end);
	*b = strtof(end + 2, NULL);
}

// TODO: Find more elegant solution for page count (there doesn't seem to be)
static int plist_page_count(plist_t objects, double page_height)
{
	const float *curves = 0;
	size_t curves_length = 0;
	plist_access(objects, 6, SESSION_OBJECTS_GLOBAL_TEXT_STORE, "Handwriting Overlay",
		     "SpatialHash", "curvespoints", &curves, &curves_length);

	// Find highest y curve-point
	double max = 0;
	for (size_t i = 0; i < curves_length / sizeof(*curves); i += 2)
		if (curves[i + 1] > max)
			max = curves[i + 1];

	return (int)(max / page_height) + 1;
}

static float plist_page_ratio(plist_t objects)
{
	float ratio = 1.414; // Default is DIN ratio because why not

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
	const char *class = 0;
	size_t class_length = 0;
	plist_access(objects, 6, SESSION_OBJECTS_GLOBAL_TEXT_STORE, "reflowState", "$class",
		     "$classname", &class, &class_length);

	double val = 500; // Default width if something fails or it's not specified

	if (!memcmp(class, "NBReflowStateReflowable", class_length)) {
		fprintf(stderr,
			"Warning: The global text store is reflowable, which isn't really supported right now. You can lock the reflow state by drawing some lines onto the document (I think)\n");
	} else if (!memcmp(class, "NBReflowStateLocked", class_length)) { // That's how I like it
		plist_access(objects, 4, SESSION_OBJECTS_GLOBAL_TEXT_STORE, "reflowState",
			     "pageWidthInDocumentCoordsKey", &val);
	} else {
		fprintf(stderr, "Unknown reflow state '%s', please report\n", class);
	}

	return val;
}

/**
 * Cairo wrappers/utilities
 */

typedef struct {
	char *data;
	size_t length;
} cairo_read_closure;

// Cairo is weird. Why can't we just pass a data buffer directly?
static cairo_status_t cairo_read(void *data, unsigned char *buf, unsigned int length)
{
	cairo_read_closure *closure = data;

	if (length > closure->length)
		return CAIRO_STATUS_READ_ERROR;

	memcpy(buf, closure->data, length);

	closure->length -= length;
	closure->data += length;

	return CAIRO_STATUS_SUCCESS;
}

static cairo_surface_t *cairo_surface_scale(cairo_surface_t *surface, float width, float height)
{
	int unscaled_width = cairo_image_surface_get_width(surface);
	int unscaled_height = cairo_image_surface_get_height(surface);
	cairo_surface_t *result = cairo_surface_create_similar(
		surface, cairo_surface_get_content(surface), width, height);
	cairo_t *cairo = cairo_create(result);
	cairo_scale(cairo, width / (float)unscaled_width, height / (float)unscaled_height);
	cairo_set_source_surface(cairo, surface, 0, 0);
	cairo_set_operator(cairo, CAIRO_OPERATOR_SOURCE);
	cairo_paint(cairo);
	cairo_destroy(cairo);
	return result;
}

cairo_surface_t *cairo_image_surface_create_from_jpeg_mem(void *data, size_t len)
{
	struct jpeg_decompress_struct jpeg;
	struct jpeg_error_mgr jpeg_err;
	jpeg.err = jpeg_std_error(&jpeg_err);
	jpeg_create_decompress(&jpeg);
	jpeg_mem_src(&jpeg, data, len);
	jpeg_read_header(&jpeg, TRUE);

#ifdef LIBJPEG_TURBO_VERSION
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	jpeg.out_color_space = JCS_EXT_BGRA;
#else
	jpeg.out_color_space = JCS_EXT_ARGB;
#endif
#else
	jpeg.out_color_space = JCS_RGB;
#endif

	jpeg_start_decompress(&jpeg);

	cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_RGB24, jpeg.output_width,
							      jpeg.output_height);
	if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
		jpeg_destroy_decompress(&jpeg);
		return surface;
	}

	while (jpeg.output_scanline < jpeg.output_height) {
		unsigned char *row_address =
			cairo_image_surface_get_data(surface) +
			(jpeg.output_scanline * cairo_image_surface_get_stride(surface));
		JSAMPROW row_pointer = row_address;
		jpeg_read_scanlines(&jpeg, &row_pointer, 1);
#ifndef LIBJPEG_TURBO_VERSION
		pix_conv(row_address, 4, row_address, 3, jpeg.output_width);
#endif
	}

	cairo_surface_mark_dirty(surface);
	jpeg_finish_decompress(&jpeg);
	jpeg_destroy_decompress(&jpeg);

	cairo_surface_set_mime_data(surface, CAIRO_MIME_TYPE_JPEG, data, len, free, data);

	return surface;
}

/**
 * Main zathura plugin implementations
 */

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
		free(note_document);
		free(root_name);
		return ZATHURA_ERROR_NOT_IMPLEMENTED;
	}

	note_document->zip = zip;
	note_document->root_name = root_name;

	note_document->width = plist_page_width(note_document->objects);
	if (note_document->width < 1) {
		fprintf(stderr, "Setting invalid width %f to 500\n", note_document->width);
		note_document->width = 500;
	}
	note_document->height = note_document->width * plist_page_ratio(note_document->objects);

	zathura_document_set_data(document, note_document);
	zathura_document_set_number_of_pages(document, plist_page_count(note_document->objects,
									note_document->height));

	return ZATHURA_ERROR_OK;
}

GIRARA_HIDDEN zathura_error_t note_document_free(zathura_document_t *document, void *data)
{
	(void)document;

	if (!data)
		return ZATHURA_ERROR_OK;

	note_document_t *note_document = data;
	zip_close(note_document->zip);
	free(note_document->root_name);
	return ZATHURA_ERROR_OK;
}

GIRARA_HIDDEN zathura_error_t note_page_init(zathura_page_t *page)
{
	note_document_t *note_document = zathura_document_get_data(zathura_page_get_document(page));
	zathura_page_set_width(page, note_document->width);
	zathura_page_set_height(page, note_document->height);

	double height = zathura_page_get_height(page);
	unsigned int number = zathura_page_get_index(page);

	note_page_t *note_page = malloc(sizeof(*note_page));
	note_page->page = page;
	note_page->start = height * number;
	note_page->end = height * (number + 1);
	zathura_page_set_data(page, note_page);

	return ZATHURA_ERROR_OK;
}

GIRARA_HIDDEN zathura_error_t note_page_clear(zathura_page_t *page, void *data)
{
	(void)page;
	free(data);
	return ZATHURA_ERROR_OK;
}

static void note_page_render_image_object(note_page_t *page, int index)
{
	note_document_t *note_document =
		zathura_document_get_data(zathura_page_get_document(page->page));
	plist_t objects = note_document->objects;

	char missing = 0;
	plist_access(objects, 6, index, "figure", "FigureBackgroundObjectKey",
		     "kImageObjectSnapshotKey", "imageIsMissing", &missing);
	if (missing)
		return;

	const char *position = 0;
	size_t position_length = 0;
	plist_access(objects, 4, index, "documentContentOrigin", &position, &position_length);
	float x, y;
	plist_string_to_floats(position, &x, &y);

	const char *size = 0;
	size_t size_length = 0;
	plist_access(objects, 4, index, "unscaledContentSize", &size, &size_length);
	float width, height;
	plist_string_to_floats(size, &width, &height);

	if (y < page->start || y + height > page->end)
		return;

	const char *path = 0;
	size_t path_length = 0;
	plist_access(objects, 7, index, "figure", "FigureBackgroundObjectKey",
		     "kImageObjectSnapshotKey", "relativePath", &path, &path_length);

	char is_jpeg = 0; // 0 means png
	plist_access(objects, 6, index, "figure", "FigureBackgroundObjectKey",
		     "kImageObjectSnapshotKey", "saveAsJPEG", &is_jpeg);

	zip_t *zip = note_document->zip;
	void *data;
	size_t length;
	zip_load(zip, note_document->root_name, path, &data, &length);
	if (!data || !length) {
		fprintf(stderr, "Invalid media object '%s' in zip\n", path);
		return;
	}

	cairo_surface_t *surface = 0;
	if (is_jpeg) {
		surface = cairo_image_surface_create_from_jpeg_mem(data, length);
	} else {
		cairo_read_closure closure = { .data = data, .length = length };
		surface = cairo_image_surface_create_from_png_stream(cairo_read, &closure);
	}

	if (!surface || cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
		fprintf(stderr, "Invalid surface from png stream\n");
		return;
	}

	surface = cairo_surface_scale(surface, width, height);

	cairo_set_source_surface(page->cairo, surface, x, y - page->start);
	cairo_paint(page->cairo);
	cairo_surface_flush(surface);
	cairo_surface_destroy(surface);
}

static void note_page_render_text_range_extract_range(plist_t objects, int range, int *start,
						      int *end)
{
	const char *range_string = 0;
	size_t range_length = 0;
	plist_access(objects, 3, range, &range_string, &range_length);
	float start_float, end_float;
	plist_string_to_floats(range_string, &start_float, &end_float);
	*start = (int)start_float;
	*end = *start + (int)end_float;
}

static void note_page_render_text_range_extract_font(plist_t objects, int font,
						     const char **font_name, int *font_size)
{
	double floating_font_size = 0;
	plist_t font_keys = plist_access(objects, 2, font, "NS.keys");
	plist_array_iter font_iter;
	plist_array_new_iter(font_keys, &font_iter);
	int font_index = 0;
	while (1) {
		plist_t key_ptr;
		plist_array_next_item(font_keys, font_iter, &key_ptr);
		if (!key_ptr)
			break;

		size_t key_index;
		plist_get_uid_val(key_ptr, &key_index);

		const char *key = 0;
		size_t key_length = 0;
		plist_access(objects, 3, key_index, &key, &key_length);
		if (!key)
			continue;

		if (!memcmp(key, "NSFontSizeAttribute", key_length)) {
			plist_access(objects, 4, font, "NS.objects", font_index,
				     &floating_font_size);
		} else if (!memcmp(key, "NSFontNameAttribute", key_length)) {
			size_t font_length; // idc, is 0-delimited anyways (I hope)
			plist_access(objects, 5, font, "NS.objects", font_index, font_name,
				     &font_length);
		} else {
			fprintf(stderr, "Unknown font attribute '%.*s', please report\n",
				(int)key_length, key);
		}

		font_index++;
	}

	*font_size = (int)floating_font_size;
}

static void note_page_render_text_range_extract_color(plist_t objects, int color, double *red,
						      double *green, double *blue, double *alpha)
{
	plist_access(objects, 3, color, "UIRed", red);
	plist_access(objects, 3, color, "UIGreen", green);
	plist_access(objects, 3, color, "UIBlue", blue);
	plist_access(objects, 3, color, "UIAlpha", alpha);
}

static int note_page_render_text_sub_range(note_page_t *page, const char *data, int range, int font,
					   int other_attributes, int color, float x, float y)
{
	note_document_t *note_document =
		zathura_document_get_data(zathura_page_get_document(page->page));
	plist_t objects = note_document->objects;

	int start, end;
	note_page_render_text_range_extract_range(objects, range, &start, &end);

	const char *font_name = 0;
	int font_size = 0;
	note_page_render_text_range_extract_font(objects, font, &font_name, &font_size);

	// TODO: Extract line-spacing, boldness, underline, etc. from other_attributes
	(void)other_attributes;

	double red, green, blue, alpha;
	note_page_render_text_range_extract_color(objects, color, &red, &green, &blue, &alpha);

	PangoFontDescription *description = pango_font_description_new();
	pango_font_description_set_absolute_size(description, font_size * PANGO_SCALE); // TODO: ?
	pango_font_description_set_family_static(description, font_name);

	PangoLayout *layout = pango_cairo_create_layout(page->cairo);
	pango_layout_set_font_description(layout, description);
	pango_layout_set_text(layout, data + start, end - start);

	cairo_move_to(page->cairo, x, y - page->start + font_size / 2);
	cairo_set_source_rgb(page->cairo, red, green, blue);
	pango_cairo_show_layout(page->cairo, layout);

	int height = pango_layout_get_line_count(layout) * font_size;

	pango_font_description_free(description);
	g_object_unref(layout);

	return height;
}

static void note_page_render_text_store(note_page_t *page, int index, float x, float y, float width,
					float height)
{
	note_document_t *note_document =
		zathura_document_get_data(zathura_page_get_document(page->page));
	plist_t objects = note_document->objects;

	const char *data = 0;
	size_t data_length = 0;
	plist_access(objects, 8, index, "NBAttributedBackingString", // TODO: Don't assume 0/1?
		     "NBAttributedBackingStringCodingKey", "NS.objects", 0, "NS.bytes", &data,
		     &data_length);
	if (!data || !data_length)
		return;

	plist_t array =
		plist_access(objects, 6, index, "NBAttributedBackingString",
			     "NBAttributedBackingStringCodingKey", "NS.objects", 1, "NS.objects");
	if (!PLIST_IS_ARRAY(array))
		return;

	plist_array_iter iter;
	plist_array_new_iter(array, &iter);
	while (1) {
		plist_t val;
		plist_array_next_item(array, iter, &val);
		if (!val)
			break;

		size_t elem_index;
		plist_get_uid_val(val, &elem_index);

		plist_t keys = plist_access(objects, 2, elem_index, "NS.keys");
		if (!PLIST_IS_ARRAY(keys))
			continue;

		int color_cross_platform, range, font, other_attributes, color;

		int index = 0;
		plist_array_iter key_iter;
		plist_array_new_iter(keys, &key_iter);
		while (1) {
			plist_t key_ptr;
			plist_array_next_item(keys, key_iter, &key_ptr);
			if (!key_ptr)
				break;

			size_t key_index;
			plist_get_uid_val(key_ptr, &key_index);

			const char *key = 0;
			size_t key_length = 0;
			plist_access(objects, 3, key_index, &key, &key_length);
			if (!key)
				continue;

			plist_t object =
				plist_access(objects, 3, elem_index, "NS.objects", index++);
			int object_index = plist_array_get_item_index(object);

			if (!memcmp(key, "subRangeColorCrossPlatformKey", key_length))
				continue; // Seems irrelevant (always like "0.0,0.0,0.0,1.0")
			else if (!memcmp(key, "subRangeRangeKey", key_length))
				range = object_index;
			else if (!memcmp(key, "subRangeFontKey", key_length))
				font = object_index;
			else if (!memcmp(key, "subRangeOtherAttributesKey", key_length))
				other_attributes = object_index;
			else if (!memcmp(key, "subRangeColorKey", key_length))
				color = object_index;
			else
				fprintf(stderr,
					"Unknown text sub range key '%.*s', please report\n",
					(int)key_length, key);
		}

		y += note_page_render_text_sub_range(page, data, range, font, other_attributes,
						     color, x, y);
	}
}

static void note_page_render_text_object(note_page_t *page, int index)
{
	note_document_t *note_document =
		zathura_document_get_data(zathura_page_get_document(page->page));
	plist_t objects = note_document->objects;

	const char *position = 0;
	size_t position_length = 0;
	plist_access(objects, 4, index, "documentContentOrigin", &position, &position_length);
	float x, y;
	plist_string_to_floats(position, &x, &y);

	const char *size = 0;
	size_t size_length = 0;
	plist_access(objects, 4, index, "unscaledContentSize", &size, &size_length);
	float width, height;
	plist_string_to_floats(size, &width, &height);

	if (y < page->start || y + height > page->end)
		return;

	plist_t text_store = plist_access(objects, 2, index, "textStore");

	note_page_render_text_store(page, plist_array_get_item_index(text_store), x, y, width,
				    height);
}

static void note_page_render_object(note_page_t *page, int index)
{
	note_document_t *note_document =
		zathura_document_get_data(zathura_page_get_document(page->page));
	plist_t objects = note_document->objects;

	const char *class = 0;
	size_t class_length = 0;
	plist_access(objects, 5, index, "$class", "$classname", &class, &class_length);

	if (!memcmp(class, "ImageMediaObject", class_length)) {
		note_page_render_image_object(page, index);
	} else if (!memcmp(class, "TextBlockMediaObject", class_length)) {
		note_page_render_text_object(page, index);
	} else {
		fprintf(stderr, "Unknown media object type '%.*s', please report\n",
			(int)class_length, class);
	}
}

// It doesn't really matter if something in here fails
static void note_page_render_objects(note_page_t *page)
{
	note_document_t *note_document =
		zathura_document_get_data(zathura_page_get_document(page->page));
	plist_t objects = note_document->objects;

	// Render the global text object
	note_page_render_text_store(page, SESSION_OBJECTS_GLOBAL_TEXT_STORE, 0, 0,
				    zathura_page_get_width(page->page),
				    zathura_page_get_height(page->page));

	plist_t objects_array = plist_access(objects, 3, SESSION_OBJECTS_GLOBAL_TEXT_STORE,
					     "mediaObjects", "NS.objects");

	plist_array_iter iter;
	plist_array_new_iter(objects_array, &iter);
	while (1) {
		plist_t val;
		plist_array_next_item(objects_array, iter, &val);
		if (!val)
			break;

		size_t index;
		plist_get_uid_val(val, &index);
		note_page_render_object(page, index);
	}
}

GIRARA_HIDDEN zathura_error_t note_page_render_cairo(zathura_page_t *page, void *data,
						     cairo_t *cairo, bool printing)
{
	if (printing)
		return ZATHURA_ERROR_NOT_IMPLEMENTED;

	note_document_t *note_document = zathura_document_get_data(zathura_page_get_document(page));
	note_page_t *note_page = data;
	note_page->cairo = cairo;

	// Render all media objects (images, ...)
	note_page_render_objects(note_page);

	plist_t overlay = plist_handwriting_overlay(note_document->objects);
	if (!overlay)
		return ZATHURA_ERROR_OK;

	/* plist_dump(note_document->objects, 0); */
	/* return ZATHURA_ERROR_OK; */

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

	if (!curves || !curves_length || !curves_num || !curves_num_length || !curves_colors ||
	    !curves_colors_length || !curves_width || !curves_width_length)
		return ZATHURA_ERROR_OK; // Arrays are empty if no lines have been drawn - that's okay!

	size_t limit = curves_num_length / sizeof(*curves_num);
	unsigned int pos = 0;
	for (size_t i = 0; i < limit; i++) {
		const unsigned int length = curves_num[i];
		const char *color = &curves_colors[i * 4];
		cairo_set_source_rgba(cairo, (float)(color[0] & 0xff) / 255,
				      (float)(color[1] & 0xff) / 255,
				      (float)(color[2] & 0xff) / 255,
				      (float)(color[3] & 0xff) / 255);

		// TODO: Fractional curve widths (?)
		cairo_set_line_width(cairo, curves_width[i]);

		if (curves[pos + 1] >= note_page->start && curves[pos + 1] <= note_page->end)
			cairo_move_to(cairo, curves[pos], curves[pos + 1] - note_page->start);

		// TODO: Render as bezier curves
		for (unsigned int j = pos; j < pos + length * 2; j += 2)
			if (curves[j + 1] >= note_page->start && curves[j + 1] <= note_page->end)
				cairo_line_to(cairo, curves[j], curves[j + 1] - note_page->start);

		cairo_stroke(cairo);
		pos += length * 2;
	}

	return ZATHURA_ERROR_OK;
}
