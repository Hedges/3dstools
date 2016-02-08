#pragma once
#include <cstdlib>
#include <string>
#include <vector>
#include <exception>
#include "types.h"
#include "libyaml/yaml.h"


class YamlException : public std::exception
{
public:
	YamlException(const std::string& error) throw()
	{
		m_What = error;
	}
	
	~YamlException() throw()
	{

	}
	
	virtual const char* what() const throw()
	{
		return m_What.c_str();
	}
private:
	std::string m_What;
};

class YamlReader
{
public:
	YamlReader();
	~YamlReader();

	void loadFile(const char *path);

	// returns a reference to the current event string
	const std::string& getEventString(void) const;

	// copies the key's value (or sequence of values) to a referenced dst
	void copyValue(std::string& dst);
	void copyValueSequence(std::vector<std::string>& dst);

	// yaml event controls
	bool getEvent();
	u32 getLevel() const;
	bool isLevelInScope(u32 level) const;
	bool isLevelSame(u32 level) const;

	bool isDone() const;

	bool isEventNothing() const;
	bool isEventScalar() const;
	bool isEventMappingStart() const;
	bool isEventMappingEnd() const;
	bool isEventSequenceStart() const;
	bool isEventSequenceEnd() const;

	bool isSequence() const;
	bool isKey() const;

private:
	// for libyaml
	FILE *m_FilePtr;
	yaml_parser_t m_Parser;
	yaml_event_t m_Event;
	bool m_IsDone;

	// for
	bool m_IsSequence;
	bool m_IsKey;
	u32 m_Level;

	std::string m_EventStr;

	void cleanup();
};