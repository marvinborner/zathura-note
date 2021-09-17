#include "plugin.h"

ZATHURA_PLUGIN_REGISTER_WITH_FUNCTIONS("note", VERSION_MAJOR, VERSION_MINOR, VERSION_REV,
				       ZATHURA_PLUGIN_FUNCTIONS({
					       .document_open = note_document_open,
					       .document_free = note_document_free,
					       .page_init = note_page_init,
					       .page_clear = note_page_clear,
					       .page_render_cairo = note_page_render_cairo,
				       }),
				       ZATHURA_PLUGIN_MIMETYPES({ "application/zip" }))
