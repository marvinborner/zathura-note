#include "plugin.h"

#include <plist/plist.h>
#include <stdio.h>
#include <zip.h>

typedef struct {
	zip_t *zip;
	plist_t session_plist;
	plist_t metadata_plist;
} note_document_t;

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
	if (length < stat.size)
		fprintf(stderr, "Unexpected size difference\n");

	plist_from_bin(bin, stat.size, plist);
	free(bin);
	return ZATHURA_ERROR_OK;
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
	if (!zip_stat_index(zip, 0, ZIP_FL_NODIR, &root_stat)) {
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
	note_document_t *note_document = data;
	zip_close(note_document->zip);
	return ZATHURA_ERROR_OK;
}

GIRARA_HIDDEN zathura_error_t note_page_init(zathura_page_t *page)
{
	// TODO: Get width dynamagically
	int width = 500;
	zathura_page_set_width(page, width);
	zathura_page_set_height(page, (int)((float)width * 1.41));

	return ZATHURA_ERROR_OK;
}

GIRARA_HIDDEN zathura_error_t note_page_clear(zathura_page_t *page, void *data)
{
	return ZATHURA_ERROR_OK;
}

// For debugging
static void plist_dump(plist_t plist, int depth)
{
	// Debug dump
	plist_dict_iter iter;
	plist_dict_new_iter(plist, &iter);
	char *key = 0;
	plist_t val;
	while (1) {
		plist_dict_next_item(plist, iter, &key, &val);
		if (!key || !val)
			break;

		printf("%s\n", key);
		for (int i = 0; i < depth; i++)
			printf(" ");
	}
}

GIRARA_HIDDEN zathura_error_t note_page_render_cairo(zathura_page_t *page, void *data,
						     cairo_t *cairo, bool printing)
{
	printf("Rendering page %d\n", zathura_page_get_index(page));
	if (printing)
		return ZATHURA_ERROR_NOT_IMPLEMENTED;

	note_document_t *note_document = data;
	plist_dump(note_document->session_plist, 0);

	/* cairo_set_source_rgba(cairo, 0xff, 0, 0, 1); */
	/* cairo_set_line_width(cairo, 1); */
	/* cairo_move_to(cairo, 0, 0); */
	/* cairo_line_to(cairo, 100, 100); */
	/* cairo_rel_line_to(cairo, 0.25, -0.125); */
	/* cairo_arc(cairo, 0.5, 0.5, 0.25 * sqrt(2), -0.25 * M_PI, 0.25 * M_PI); */
	/* cairo_rel_curve_to(cairo, -0.25, -0.125, -0.25, 0.125, -0.5, 0); */
	/* cairo_close_path(cairo); */
	/* cairo_stroke(cairo); */

	return ZATHURA_ERROR_OK;
}
