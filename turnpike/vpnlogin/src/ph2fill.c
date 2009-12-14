
/************************************************************************************
*   Copyright (c) 2005, Novell Inc.,                                                * 
*   All rights reserved.                                                            *
*                                                                                   *
*   Redistribution and use in source and binary forms, with or without              *
*   modification, are permitted provided that the following conditions              *
*   are met:                                                                        *
*   1.  Redistributions of source code must retain the above copyright              *
*       notice, this list of conditions and the following disclaimer.               *
*   2.  Redistributions in binary form must reproduce the above copyright           *
*       notice, this list of conditions and the following disclaimer in the         *
*       documentation and/or other materials provided with the distribution.        *
*   3.  Neither the name of the Novell nor the names of its contributors            *
*       may be used to endorse or promote products derived from this software       *
*       without specific prior written permission.                                  *
*   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND *
*   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE           *
*   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE      *
*   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE *
*   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL      *
*   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS         *
*   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)           *
*   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT      *
*   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY       *
*   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF          *
*   SUCH DAMAGE.                                                                    *
*************************************************************************************/

#include <utility.h>
#include <gtk/gtk.h>

#include "externs.h"

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include "CommonUI.h"

extern Inf_t Inf;
extern char* errString(int, char*);
extern int writePhase2ProposalsToFile(xmlNode *policy_node);

typedef struct
{
  gchar   *network;
  gchar   *mask;
  gboolean editable;
}
Item;

GtkTreeModel *model;
int addsighandler = 0, remsighandler = 0;

enum
{
	COLUMN_NETWORK,
	COLUMN_MASK,
	COLUMN_EDITABLE,
	NUM_COLUMNS
};

static GArray *articles = NULL;

static void
add_items (xmlNode *policy_node)
{
  	Item foo;
	xmlChar *buffer = NULL;
	xmlNode *cur_node = NULL;
  g_return_if_fail (articles != NULL);

 

	if(policy_node == NULL)
		return ;
	
	for(cur_node = policy_node->children; cur_node != NULL;  cur_node = cur_node->next)
	{
		if ( policy_node->type == XML_ELEMENT_NODE  ) 
		{
			if(strcmp((const char*)cur_node->name, "entry") == 0)
			{
				buffer= xmlGetProp(cur_node,(const xmlChar *)"network");
				if(buffer)
				{
					foo.network = g_strdup ((char*)buffer);
					xmlFree(buffer);
				}
				buffer= xmlGetProp(cur_node,(const xmlChar *)"mask");
				if(buffer)
				{
					foo.mask = g_strdup ((char*)buffer);
					xmlFree(buffer);
				}
				foo.editable = TRUE;
				g_array_append_vals (articles, &foo, 1);
			}
		}
	}
  
  

}

static GtkTreeModel *
create_model (xmlNode *policy_node)
{
  gint i = 0;
  GtkListStore *model;
  GtkTreeIter iter;
	xmlNode *cur_node = NULL, *networks_node = NULL;
      

  /* create array */
  articles = g_array_sized_new (FALSE, FALSE, sizeof (Item), 1);
  /* create list store */
  model = gtk_list_store_new (NUM_COLUMNS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN);

  if(policy_node)
  	for(cur_node = policy_node->children; cur_node != NULL;  cur_node = cur_node->next)
	{
		if ( policy_node->type == XML_ELEMENT_NODE  ) 
		{
			if(strcmp((const char*)cur_node->name, "networks") == 0)
			{
				networks_node = cur_node;
				break;
			}
		}
	}

  add_items (networks_node);
    

  /* add items */
  
  for (i = 0; i < articles->len; i++)
    {
      gtk_list_store_append (model, &iter);

      
      gtk_list_store_set (model, &iter,
			  COLUMN_NETWORK,
			  g_array_index (articles, Item, i).network,
			  COLUMN_MASK,
			  g_array_index (articles, Item, i).mask,
			  COLUMN_EDITABLE,
			  g_array_index (articles, Item, i).editable,
			  -1);
	
    }

  return GTK_TREE_MODEL (model);
}

static void
add_item (GtkWidget *button, gpointer data)
{
  Item foo;
  GtkTreeIter iter;

  g_return_if_fail (articles != NULL);
  
  
  foo.network = g_strdup("xxx.xxx.xxx.xxx");
  foo.mask = g_strdup ("yyy.yyy.yyy.yyy");
  foo.editable = TRUE;
  g_array_append_vals (articles, &foo, 1);

  gtk_list_store_append (GTK_LIST_STORE (model), &iter);
  gtk_list_store_set (GTK_LIST_STORE (model), &iter,
		      COLUMN_NETWORK, foo.network,
		      COLUMN_MASK, foo.mask,
		      COLUMN_EDITABLE, foo.editable,
		      -1);
}

static void
remove_item (GtkWidget *widget, gpointer data)
{
  GtkTreeIter iter;
  GtkTreeView *treeview = (GtkTreeView *)data;
  GtkTreeModel *model = gtk_tree_view_get_model (treeview);
  GtkTreeSelection *selection = gtk_tree_view_get_selection (treeview);

  if (gtk_tree_selection_get_selected (selection, NULL, &iter))
    {
      gint i;
      GtkTreePath *path;

      path = gtk_tree_model_get_path (model, &iter);
      i = gtk_tree_path_get_indices (path)[0];
      gtk_list_store_remove (GTK_LIST_STORE (model), &iter);

      g_array_remove_index (articles, i);

      gtk_tree_path_free (path);
    }
}

static void
cell_edited (GtkCellRendererText *cell,
	     const gchar         *path_string,
	     const gchar         *new_text,
	     gpointer             data)
{
  GtkTreeModel *model = (GtkTreeModel *)data;
  GtkTreePath *path = gtk_tree_path_new_from_string (path_string);
  GtkTreeIter iter;
	struct sockaddr_in addr;
	
  gint column = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (cell), "column"));

  gtk_tree_model_get_iter (model, &iter, path);

  switch (column)
    {
    case COLUMN_NETWORK:
      {
	gint i;
	if ( inet_aton(new_text, &addr.sin_addr) == 0 )
	{
		show_dialog_message(errString(INVALID_PH2_NETWORK, Inf.errStr));
		break;
	}
	i = gtk_tree_path_get_indices (path)[0];
	g_array_index (articles, Item, i).network = g_strdup (new_text);

	gtk_list_store_set (GTK_LIST_STORE (model), &iter, column,
			    g_array_index (articles, Item, i).network, -1);
      }
      break;

    case COLUMN_MASK:
      {
	gint i;
	gchar *old_text;
	if ( inet_aton(new_text, &addr.sin_addr) == 0 )
	{
		show_dialog_message(errString(INVALID_PH2_MASK, Inf.errStr));
		break;
	}
	
        gtk_tree_model_get (model, &iter, column, &old_text, -1);
	g_free (old_text);

	i = gtk_tree_path_get_indices (path)[0];
	g_free (g_array_index (articles, Item, i).mask);
	g_array_index (articles, Item, i).mask = g_strdup (new_text);

	gtk_list_store_set (GTK_LIST_STORE (model), &iter, column,
                            g_array_index (articles, Item, i).mask, -1);
      }
      break;
    }

  gtk_tree_path_free (path);
}

static void
add_columns (GtkTreeView *treeview)
{
  GtkCellRenderer *renderer;
  GtkTreeModel *model = gtk_tree_view_get_model (treeview);
  int columns = 0;
  GtkTreeViewColumn *current_column = NULL;
  
  
  /* remove the existing columns */
  
  while((current_column = (gtk_tree_view_get_column (treeview,0))))
  {
  	columns = gtk_tree_view_remove_column(treeview, current_column);
  }
  
  /* number column */
  renderer = gtk_cell_renderer_text_new ();
  g_signal_connect (renderer, "edited",
		    G_CALLBACK (cell_edited), model);
  g_object_set_data (G_OBJECT (renderer), "column", (gint *)COLUMN_NETWORK);

  gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (treeview),
					       -1, "Network", renderer,
					       "text", COLUMN_NETWORK,
					       "editable", COLUMN_EDITABLE,
					       NULL);

  /* product column */
  renderer = gtk_cell_renderer_text_new ();
  g_signal_connect (renderer, "edited",
		    G_CALLBACK (cell_edited), model);
  g_object_set_data (G_OBJECT (renderer), "column", (gint *)COLUMN_MASK);

  gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (treeview),
					       -1, "Mask", renderer,
					       "text", COLUMN_MASK,
					       "editable", COLUMN_EDITABLE,
					       NULL);
}

void fillup_ike_ph2_params(xmlNode *policy_node)
{
      
      GtkWidget *treeview;

      /* create model */
      model = create_model (policy_node);
      /* create tree view */
      gtk_tree_view_set_model(GTK_TREE_VIEW(ph2treeview), NULL);
      treeview = ph2treeview;
      gtk_tree_view_set_model(GTK_TREE_VIEW(treeview), model);
      g_object_unref (model);
      gtk_tree_view_set_rules_hint (GTK_TREE_VIEW (treeview), TRUE);
      gtk_tree_selection_set_mode (gtk_tree_view_get_selection (GTK_TREE_VIEW (treeview)),
				   GTK_SELECTION_SINGLE);

      add_columns (GTK_TREE_VIEW (treeview));

	if(addsighandler)
	{
		g_signal_handler_disconnect(G_OBJECT(addbtn), addsighandler);
		addsighandler = 0;
	}

	if(remsighandler)
	{
		g_signal_handler_disconnect(G_OBJECT(rembtn), remsighandler);
		remsighandler = 0;
	}
	
		
      addsighandler = g_signal_connect (addbtn, "clicked",
			G_CALLBACK (add_item), model);
      remsighandler = g_signal_connect (rembtn, "clicked",
			G_CALLBACK (remove_item), treeview);


  return;
}

void writePhase2PoliciesToFile(xmlNode *policy_node)
{
	xmlNodePtr childptr = NULL, entryptr = NULL, networksptr = NULL;
	int i;
	struct sockaddr_in addr;
	
	networksptr=xmlNewChild(policy_node,NULL,(const xmlChar *)"phase2", NULL);
	writePhase2ProposalsToFile(networksptr);
	childptr=xmlNewChild(networksptr,NULL,(const xmlChar *)"networks", NULL);
	
	g_return_if_fail (articles != NULL);
		
	for (i = 0; i < articles->len; i++)
	{
		if ( inet_aton(g_array_index (articles, Item, i).network, &addr.sin_addr) == 0 )
		{
			continue;
		}
		else if ( inet_aton(g_array_index (articles, Item, i).mask, &addr.sin_addr) == 0 )
		{
			continue;
		}
		entryptr=xmlNewChild(childptr,NULL,(const xmlChar *)"entry", NULL);
		xmlNewProp(entryptr,(const xmlChar *)"network", (const xmlChar *)g_array_index (articles, Item, i).network);
		xmlNewProp(entryptr,(const xmlChar *)"mask", (const xmlChar *)g_array_index (articles, Item, i).mask);
	}
	
	return ;
}
