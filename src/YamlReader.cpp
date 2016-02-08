#include "YamlReader.h"

YamlReader::YamlReader() :
	m_FilePtr(NULL),
	m_IsDone(false),
	m_Level(0),
	m_EventStr("")
{
}

YamlReader::~YamlReader()
{
	cleanup();
}

void YamlReader::loadFile(const char * path)
{
	// do some cleanup before a file is loaded
	cleanup();
	
	// Create Parser Object
	yaml_parser_initialize(&m_Parser);

	// Open the file
	m_FilePtr = fopen(path, "rb");
	if (m_FilePtr == NULL) 
	{
		throw YamlException("Failed to open: " + std::string(path));
	}

	// Associate file with parser object
	yaml_parser_set_input_file(&m_Parser, m_FilePtr);

	// Set initial conditions
	m_IsSequence = false;
	m_IsKey = true;
	m_Level = 0;

	// Read the event sequence until the first mapping appears
	while (getEvent() && !isEventMappingStart());
}

const std::string & YamlReader::getEventString(void) const
{
	return m_EventStr;
}

void YamlReader::copyValue(std::string & dst)
{
	std::string key = getEventString();

	if (!getEvent() || !isEventScalar()) 
	{
		throw YamlException("Item '" + key + "' requires a value");
	}

	dst = std::string(getEventString());
}

void YamlReader::copyValueSequence(std::vector<std::string>& dst)
{
	if (!getEvent() || !isEventSequenceStart())
	{
		throw YamlException("Bad formatting, expected sequence");
	}

	dst.clear();

	u32 initLevel = getLevel();
	while (getEvent() && isLevelSame(initLevel)) 
	{
		if (isEventScalar() && !getEventString().empty())
		{
			dst.push_back(getEventString());
		}
	}
}

bool YamlReader::getEvent()
{
	/* Finish Previous Event */
	if (!isEventNothing())
	{
		if (isEventScalar() && !m_IsSequence)
		{
			m_IsKey = !m_IsKey;
		}

		yaml_event_delete(&m_Event);
	}

	/* Get new event */
	if (yaml_parser_parse(&m_Parser, &m_Event) != 1)
	{
		throw YamlException("(libyaml) " + std::string(m_Parser.context) + ", " + std::string(m_Parser.problem));
	}

	/* Clean string */
	m_EventStr.clear();

	/* Process Event */
	switch (m_Event.type) 
	{
		case YAML_NO_EVENT:
			break;
		case YAML_STREAM_START_EVENT:
			break;
		case YAML_DOCUMENT_START_EVENT:
			break;
		case YAML_ALIAS_EVENT:
			break;
		case YAML_SCALAR_EVENT:
			m_EventStr = std::string(reinterpret_cast<char*>(m_Event.data.scalar.value));
			break;
		case YAML_SEQUENCE_START_EVENT:
			m_IsSequence = true;
			m_IsKey = false;
			m_Level++;
			break;
		case YAML_SEQUENCE_END_EVENT:
			m_IsSequence = false;
			m_IsKey = true;
			m_Level--;
			break;
		case YAML_MAPPING_START_EVENT:
			m_IsKey = true;
			m_Level++;
			break;
		case YAML_MAPPING_END_EVENT:
			m_IsKey = true;
			m_Level--;
			break;
		case YAML_DOCUMENT_END_EVENT:
		case YAML_STREAM_END_EVENT:
			m_IsDone = true;
			break;
		default: break;
	}

	return !isDone();
}

u32 YamlReader::getLevel() const
{
	return m_Level;
}

bool YamlReader::isLevelInScope(u32 level) const
{
	return m_Level >= level;
}

bool YamlReader::isLevelSame(u32 level) const
{
	return m_Level == level;
}

bool YamlReader::isDone() const
{
	return m_IsDone;
}

bool YamlReader::isEventNothing() const
{
	return m_Event.type == YAML_NO_EVENT;
}

bool YamlReader::isEventScalar() const
{
	return m_Event.type == YAML_SCALAR_EVENT;
}

bool YamlReader::isEventMappingStart() const
{
	return m_Event.type == YAML_MAPPING_START_EVENT;
}

bool YamlReader::isEventMappingEnd() const
{
	return m_Event.type == YAML_MAPPING_END_EVENT;
}

bool YamlReader::isEventSequenceStart() const
{
	return m_Event.type == YAML_SEQUENCE_START_EVENT;
}

bool YamlReader::isEventSequenceEnd() const
{
	return m_Event.type == YAML_SEQUENCE_END_EVENT;
}

bool YamlReader::isSequence() const
{
	return m_IsSequence;
}

bool YamlReader::isKey() const
{
	return m_IsKey;
}

void YamlReader::cleanup()
{
	if (m_FilePtr != NULL)
	{
		yaml_parser_delete(&m_Parser);
		fclose(m_FilePtr);
		m_FilePtr = NULL;
	}
}
