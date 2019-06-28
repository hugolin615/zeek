// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

#include <sstream>
#include <errno.h>
#include <math.h>
#include <stdint.h>

#include "JSON.h"

using namespace threading::formatter;
using nlohmann::json;

JSON::JSON(MsgThread* t, TimeFormat tf) : Formatter(t), surrounding_braces(true)
	{
	timestamps = tf;
	}

JSON::~JSON()
	{
	}

bool JSON::Describe(ODesc* desc, int num_fields, const Field* const * fields,
					Value** vals) const
	{
	json j = json::object();

	for ( int i = 0; i < num_fields; i++ )
		{
		if ( vals[i]->present )
			{
			json new_entry = BuildJSON(vals[i]);
			if ( new_entry.is_null() )
				return false;

			j[fields[i]->name] = new_entry;
			}
		}

	desc->Add(j.dump());

	return true;
	}

bool JSON::Describe(ODesc* desc, Value* val, const string& name) const
	{
	if ( desc->IsBinary() )
		{
		GetThread()->Error("json formatter: binary format not supported");
		return false;
		}

	if ( ! val->present )
		return true;

	json j = BuildJSON(val, name);
	if ( j.is_null() )
		return false;

	desc->Add(j.dump());
	return true;
	}

threading::Value* JSON::ParseValue(const string& s, const string& name, TypeTag type, TypeTag subtype) const
	{
	GetThread()->Error("JSON formatter does not support parsing yet.");
	return NULL;
	}

json JSON::BuildJSON(Value* val, const string& name) const
	{
	json j;
	switch ( val->type )
		{
		case TYPE_BOOL:
			j = val->val.int_val != 0;
			break;

		case TYPE_INT:
			j = val->val.int_val;
			break;

		case TYPE_COUNT:
		case TYPE_COUNTER:
			j = val->val.uint_val;
			break;

		case TYPE_PORT:
			j = val->val.port_val.port;
			break;

		case TYPE_SUBNET:
			j = Formatter::Render(val->val.subnet_val);
			break;

		case TYPE_ADDR:
			j = Formatter::Render(val->val.addr_val);
			break;

		case TYPE_DOUBLE:
		case TYPE_INTERVAL:
			j = val->val.double_val;
			break;

		case TYPE_TIME:
			{
			if ( timestamps == TS_ISO8601 )
				{
				char buffer[40];
				char buffer2[40];
				time_t the_time = time_t(floor(val->val.double_val));
				struct tm t;

				if ( ! gmtime_r(&the_time, &t) ||
					 ! strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &t) )
					{
					GetThread()->Error(GetThread()->Fmt("json formatter: failure getting time: (%lf)", val->val.double_val));
					// This was a failure, doesn't really matter what gets put here
					// but it should probably stand out...
					j = "2000-01-01T00:00:00.000000";
					}
				else
					{
					double integ;
					double frac = modf(val->val.double_val, &integ);

					if ( frac < 0 )
						frac += 1;

					snprintf(buffer2, sizeof(buffer2), "%s.%06.0fZ", buffer, fabs(frac) * 1000000);
					j = buffer2;
					}
				}

			else if ( timestamps == TS_EPOCH )
				j = val->val.double_val;

			else if ( timestamps == TS_MILLIS )
				{
				// ElasticSearch uses milliseconds for timestamps
				j = (uint64_t) (val->val.double_val * 1000);
				}

			break;
			}

		case TYPE_ENUM:
		case TYPE_STRING:
		case TYPE_FILE:
		case TYPE_FUNC:
			{
			string output;
			for ( int i = 0; i < val->val.string_val.length; ++i )
				{
				char c = val->val.string_val.data[i];

				// 2byte Unicode escape special characters.
				if ( c < 32 || c > 126 || c == '\n' || c == '"' || c == '\'' || c == '\\' || c == '&' )
					{
					output.append("\\u00");
					char hex[2] = {'0', '0'};
					bytetohex(c, hex);
					output.push_back(hex[0]);
					output.push_back(hex[1]);
					}
				else
					output.push_back(c);
				}

			j = output;
			break;
			}

		case TYPE_TABLE:
			{
			j = json::array();

			for ( int idx = 0; idx < val->val.set_val.size; idx++ )
				j.push_back(BuildJSON(val->val.set_val.vals[idx]));

			break;
			}

		case TYPE_VECTOR:
			{
			j = json::array();

			for ( int idx = 0; idx < val->val.vector_val.size; idx++ )
				j.push_back(BuildJSON(val->val.vector_val.vals[idx]));

			break;
			}

		default:
			break;
		}

	if ( ! name.empty() && ! j.is_null() )
		{
		json j2 = json::object();
		j2[name] = j;
		return j2;
		}

	return j;
	}
